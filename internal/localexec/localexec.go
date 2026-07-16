// Package localexec is the process boundary for the explicit host-local tools.
// It resolves only allowlisted executables, gives every child a private state
// tree and minimal environment, and bounds all captured output.
package localexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
)

const (
	// DefaultWaitDelay bounds how long Wait may remain blocked on inherited
	// pipes after a child exits or its context is cancelled.
	DefaultWaitDelay = 10 * time.Second

	// CleanPath is deliberately compiled in rather than inherited. The
	// selected executable is always invoked by canonical absolute path; PATH
	// exists only for trusted interpreters and helper processes it may start.
	CleanPath = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
)

var allowedTools = map[string]struct{}{
	"bun":         {},
	"npm":         {},
	"osv-scanner": {},
	"pip":         {},
	"pip-compile": {},
	"pnpm":        {},
	"poetry":      {},
	"trivy":       {},
	"uv":          {},
}

// Resolver locates one executable name. Production uses exec.LookPath; tests
// inject a resolver so provenance checks never execute the selected file.
type Resolver func(string) (string, error)

// Resolve returns a canonical absolute executable outside root. Only compiled-
// in tool names are accepted, and the resolved file must not be writable by its
// group or by other users. Approved parent roots and ownership-chain checks are
// intentionally a separate hardening step.
func Resolve(root, name string, resolver Resolver) (string, error) {
	if _, ok := allowedTools[name]; !ok {
		return "", fmt.Errorf("local tool %q is not allowlisted", name)
	}
	if resolver == nil {
		resolver = exec.LookPath
	}
	path, err := resolver(name)
	if err != nil {
		return "", fmt.Errorf("local tool %s is not available on the system PATH: %w", name, err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("make local tool %s path absolute: %w", name, err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve local tool %s: %w", name, err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", fmt.Errorf("make canonical local tool %s path absolute: %w", name, err)
	}
	if root != "" {
		canonicalRoot, rootErr := canonicalDirectory(root)
		if rootErr != nil {
			return "", fmt.Errorf("resolve local tool target root: %w", rootErr)
		}
		if pathWithin(canonicalRoot, canonical) {
			return "", fmt.Errorf("local tool %s resolves inside the target project and is not allowed", name)
		}
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat local tool %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("local tool %s is not a regular executable", name)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("local tool %s is group- or world-writable", name)
	}
	return canonical, nil
}

func canonicalDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("target root is not a directory")
	}
	return canonical, nil
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// Environment owns one invocation's private state. Variables returns a fresh
// copy of the minimal child environment; Close removes the whole state tree.
type Environment struct {
	root      string
	variables []string
}

// NewEnvironment creates private HOME, cache, configuration, and temporary
// directories. It never copies caller variables, including credentials,
// proxies, package-manager settings, or language runtime configuration.
func NewEnvironment() (*Environment, error) {
	root, err := os.MkdirTemp("", "vuelta-local-tool-")
	if err != nil {
		return nil, fmt.Errorf("create private local-tool state: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	if err := os.Chmod(root, 0o700); err != nil {
		cleanup()
		return nil, fmt.Errorf("restrict private local-tool state: %w", err)
	}
	directories := map[string]string{
		"home":   filepath.Join(root, "home"),
		"cache":  filepath.Join(root, "cache"),
		"config": filepath.Join(root, "config"),
		"tmp":    filepath.Join(root, "tmp"),
	}
	for _, path := range directories {
		if err := os.Mkdir(path, 0o700); err != nil {
			cleanup()
			return nil, fmt.Errorf("create private local-tool directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			cleanup()
			return nil, fmt.Errorf("restrict private local-tool directory: %w", err)
		}
	}
	return &Environment{
		root: root,
		variables: []string{
			"PATH=" + CleanPath,
			"HOME=" + directories["home"],
			"XDG_CACHE_HOME=" + directories["cache"],
			"XDG_CONFIG_HOME=" + directories["config"],
			"TMPDIR=" + directories["tmp"],
			"TMP=" + directories["tmp"],
			"TEMP=" + directories["tmp"],
			"NO_COLOR=1",
		},
	}, nil
}

// Root returns the invocation state root for lifecycle and permission checks.
func (e *Environment) Root() string { return e.root }

// Variables returns a copy so callers cannot mutate the environment retained
// for subsequent inspection.
func (e *Environment) Variables() []string {
	return append([]string(nil), e.variables...)
}

// Close removes all invocation state.
func (e *Environment) Close() error {
	if e == nil || e.root == "" {
		return nil
	}
	err := os.RemoveAll(e.root)
	e.root = ""
	e.variables = nil
	return err
}

// Result preserves an expected non-zero child exit status separately from
// failures to start, cancel, wait for, or safely capture the process.
type Result struct {
	Output   []byte
	Stderr   []byte
	ExitCode int
}

// OutputLimitError reports a hard structured-output limit.
type OutputLimitError struct{ Bytes int }

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("local tool output exceeded %d bytes", e.Bytes)
}

// RunTail retains only the most recent output while allowing the child to
// finish. It is appropriate for mixed diagnostic/package-manager output.
func RunTail(ctx context.Context, binary, dir string, args, env []string, bytes int) (Result, error) {
	tail := capio.NewTail(bytes)
	return run(ctx, binary, dir, args, env, tail, func() []byte { return []byte(tail.String()) })
}

// RunLimit captures a complete structured document and cancels the child when
// the cap is exceeded, so callers never parse a truncated successful report.
func RunLimit(ctx context.Context, binary, dir string, args, env []string, bytes int) (Result, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	limit := capio.NewLimit(bytes, cancel)
	result, err := run(runCtx, binary, dir, args, env, limit, limit.Bytes)
	if limit.Exceeded() {
		return result, &OutputLimitError{Bytes: bytes}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, ctxErr
	}
	return result, err
}

// RunStructured hard-limits stdout while retaining only a diagnostic stderr
// tail. This keeps scanner JSON complete and separate from progress messages.
func RunStructured(ctx context.Context, binary, dir string, args, env []string, stdoutBytes, stderrBytes int) (Result, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := capio.NewLimit(stdoutBytes, cancel)
	stderr := capio.NewTail(stderrBytes)
	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Dir = dir
	cmd.Env = append([]string(nil), env...)
	cmd.WaitDelay = DefaultWaitDelay
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	result := Result{Output: stdout.Bytes(), Stderr: []byte(stderr.String())}
	if stdout.Exceeded() {
		return result, &OutputLimitError{Bytes: stdoutBytes}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, ctxErr
	}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return Result{}, err
}

type outputWriter interface {
	Write([]byte) (int, error)
}

func run(ctx context.Context, binary, dir string, args, env []string, output outputWriter, captured func() []byte) (Result, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = append([]string(nil), env...)
	cmd.WaitDelay = DefaultWaitDelay
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	result := Result{Output: captured()}
	if err == nil {
		return result, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, ctxErr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return Result{}, err
}
