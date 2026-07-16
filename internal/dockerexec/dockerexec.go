// Package dockerexec is the single process boundary for Docker CLI commands.
// It binds commands to one verified absolute executable and runs them with a
// minimal environment and bounded output collectors.
package dockerexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
)

const defaultWaitDelay = 10 * time.Second

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CaptureMode selects how a child stream is handled.
type CaptureMode uint8

const (
	// Discard drops the stream without attaching it to the parent process.
	Discard CaptureMode = iota
	// Tail retains a bounded diagnostic tail and lets the command continue.
	Tail
	// Limit retains a bounded prefix and cancels the command on overflow.
	Limit
)

// Capture configures bounded collection for one child stream.
type Capture struct {
	Mode  CaptureMode
	Bytes int
}

// Request describes one Docker CLI invocation. Args never includes the
// executable name. Env is deliberately restricted to boundary-approved keys.
type Request struct {
	Args      []string
	Dir       string
	Env       map[string]string
	Stdin     io.Reader
	Stdout    Capture
	Stderr    Capture
	Combined  Capture
	WaitDelay time.Duration
}

// Result contains only the explicitly requested, bounded child output.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	Combined []byte
}

// Runner is the common Docker execution interface used by production stages.
type Runner interface {
	Path() (string, error)
	Run(context.Context, Request) (Result, error)
}

// Resolver resolves the Docker CLI name. Production uses exec.LookPath;
// tests inject it to assert that resolution happens only once.
type Resolver func(string) (string, error)

// CommandRunner starts the already-resolved executable. It exists so boundary
// tests can inspect the exact path and environment without starting a child.
type CommandRunner func(context.Context, string, Request, []string) (Result, error)

// Options supplies test seams. Zero values select hardened production
// behavior. ConfigDir, when set, must name a new or protected empty directory.
type Options struct {
	Resolver      Resolver
	CommandRunner CommandRunner
	ConfigDir     string
}

// Executor binds all of its invocations to one resolved Docker CLI and one
// empty, protected Docker configuration directory.
type Executor struct {
	options Options
	once    sync.Once
	path    string
	env     []string
	err     error
}

// New returns a lazily initialized executor. The first Path or Run call fixes
// the executable and environment for the lifetime of the executor.
func New(options Options) *Executor { return &Executor{options: options} }

var defaultExecutor Runner = New(Options{})

// Default returns the process-wide production executor.
func Default() Runner { return defaultExecutor }

// Path returns the verified absolute Docker CLI path.
func (e *Executor) Path() (string, error) {
	e.initialize()
	return e.path, e.err
}

// Run executes one Docker command with the fixed executable and minimal
// environment. Errors never include argv, environment, or command output.
func (e *Executor) Run(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	e.initialize()
	if e.err != nil {
		return Result{}, e.err
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	environment := append([]string(nil), e.env...)
	for name, value := range request.Env {
		environment = append(environment, name+"="+value)
	}
	sort.Strings(environment)
	run := e.options.CommandRunner
	if run == nil {
		run = runCommand
	}
	return run(ctx, e.path, request, environment)
}

func (e *Executor) initialize() {
	e.once.Do(func() {
		resolve := e.options.Resolver
		if resolve == nil {
			resolve = exec.LookPath
		}
		path, err := resolve("docker")
		if err != nil {
			e.err = fmt.Errorf("resolve approved Docker CLI: %w", err)
			return
		}
		path, err = filepath.Abs(path)
		if err != nil {
			e.err = fmt.Errorf("resolve approved Docker CLI absolute path: %w", err)
			return
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			e.err = fmt.Errorf("resolve approved Docker CLI symlinks: %w", err)
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			e.err = fmt.Errorf("inspect approved Docker CLI: %w", err)
			return
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			e.err = errors.New("approved Docker CLI is not an executable regular file")
			return
		}
		if info.Mode().Perm()&0o022 != 0 {
			e.err = errors.New("approved Docker CLI is writable by group or other")
			return
		}
		if err := validateOwner(info); err != nil {
			e.err = err
			return
		}

		configDir, err := prepareConfigDir(e.options.ConfigDir)
		if err != nil {
			e.err = err
			return
		}
		e.path = path
		e.env = []string{"DOCKER_CONFIG=" + configDir}
	})
}

func prepareConfigDir(path string) (string, error) {
	var err error
	if path == "" {
		path, err = os.MkdirTemp("", "vuelta-docker-config-")
	} else {
		err = os.Mkdir(path, 0o700)
		if os.IsExist(err) {
			err = nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("create isolated Docker config: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect isolated Docker config: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("isolated Docker config must be a 0700 directory")
	}
	configPath := filepath.Join(path, "config.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		return "", fmt.Errorf("initialize isolated Docker config: %w", err)
	}
	return path, nil
}

func validateRequest(request Request) error {
	if len(request.Args) == 0 {
		return errors.New("docker argv is required")
	}
	if request.Combined.Mode != Discard && (request.Stdout.Mode != Discard || request.Stderr.Mode != Discard) {
		return errors.New("combined Docker capture cannot be mixed with stdout/stderr capture")
	}
	for _, capture := range []Capture{request.Stdout, request.Stderr, request.Combined} {
		if capture.Mode > Limit || (capture.Mode != Discard && capture.Bytes <= 0) {
			return errors.New("invalid Docker output capture policy")
		}
	}
	for name, value := range request.Env {
		if name != "VUELTA_IMAGE" {
			return fmt.Errorf("docker environment key %q is not allowlisted", name)
		}
		if !envName.MatchString(name) || strings.ContainsRune(value, '\x00') {
			return errors.New("invalid Docker environment entry")
		}
	}
	return nil
}

// CommandError reports a Docker CLI failure without exposing untrusted
// arguments, environment values, or child output.
type CommandError struct{ err error }

func (e *CommandError) Error() string { return "docker command failed" }
func (e *CommandError) Unwrap() error { return e.err }

// OutputLimitError reports which structured stream exceeded its hard cap.
type OutputLimitError struct {
	Stream string
	Limit  int
}

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("docker %s exceeded %d bytes", e.Stream, e.Limit)
}

type collector struct {
	mode  CaptureMode
	limit int
	tail  *capio.Tail
	hard  *capio.Limit
}

func newCollector(capture Capture, cancel context.CancelFunc) *collector {
	c := &collector{mode: capture.Mode, limit: capture.Bytes}
	switch capture.Mode {
	case Tail:
		c.tail = capio.NewTail(capture.Bytes)
	case Limit:
		c.hard = capio.NewLimit(capture.Bytes, cancel)
	}
	return c
}

func (c *collector) writer() io.Writer {
	if c.tail != nil {
		return c.tail
	}
	if c.hard != nil {
		return c.hard
	}
	return nil
}

func (c *collector) bytes() []byte {
	if c.tail != nil {
		return []byte(c.tail.String())
	}
	if c.hard != nil {
		return c.hard.Bytes()
	}
	return nil
}

func (c *collector) exceeded() bool { return c.hard != nil && c.hard.Exceeded() }

func runCommand(ctx context.Context, path string, request Request, environment []string) (Result, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := newCollector(request.Stdout, cancel)
	stderr := newCollector(request.Stderr, cancel)
	combined := newCollector(request.Combined, cancel)

	cmd := exec.CommandContext(runCtx, path, request.Args...)
	cmd.Dir = request.Dir
	cmd.Env = environment
	cmd.Stdin = request.Stdin
	cmd.WaitDelay = request.WaitDelay
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = defaultWaitDelay
	}
	if combined.writer() != nil {
		cmd.Stdout = combined.writer()
		cmd.Stderr = combined.writer()
	} else {
		cmd.Stdout = stdout.writer()
		cmd.Stderr = stderr.writer()
	}
	err := cmd.Run()
	result := Result{Stdout: stdout.bytes(), Stderr: stderr.bytes(), Combined: combined.bytes()}
	for stream, c := range map[string]*collector{"stdout": stdout, "stderr": stderr, "output": combined} {
		if c.exceeded() {
			return result, &OutputLimitError{Stream: stream, Limit: c.limit}
		}
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		return result, &CommandError{err: err}
	}
	return result, nil
}
