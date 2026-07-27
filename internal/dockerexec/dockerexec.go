// Package dockerexec is the single process boundary for Docker CLI commands.
// It binds commands to one verified absolute executable and approved local
// Unix socket, attests daemon identity/capabilities, and runs every command
// with a minimal environment and bounded output collectors.
package dockerexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
)

const defaultWaitDelay = 10 * time.Second

const daemonOutputLimit = 32 << 10

var daemonProbeTimeout = 30 * time.Second

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
	// Excerpt retains bounded first and last diagnostic context.
	Excerpt
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

// EndpointValidator canonicalizes and validates a configured endpoint. Tests
// may inject it when the platform test sandbox cannot create a protected Unix
// socket parent hierarchy.
type EndpointValidator func(Endpoint) (string, error)

// Endpoint is the complete authority for one local Docker daemon. SocketPath
// is canonicalized and validated before use; Expected is attested before the
// first caller command runs.
type Endpoint struct {
	SocketPath string
	Expected   DaemonIdentity
}

// DaemonIdentity pins stable daemon identity and the minimum capabilities
// required by Vuelta. SecurityOptions are exact entries reported by
// `docker info`; every configured entry must be present.
type DaemonIdentity struct {
	ID                      string
	ServerVersion           string
	OperatingSystem         string
	Architecture            string
	MinimumAPIVersion       string
	RequiredSecurityOptions []string
}

// AttestationError means the configured daemon failed identity or capability
// verification before a caller command was allowed to run.
type AttestationError struct{ Err error }

func (e *AttestationError) Error() string {
	return "Docker daemon attestation failed: " + e.Err.Error()
}
func (e *AttestationError) Unwrap() error { return e.Err }

// Options supplies the approved endpoint plus test seams. A zero Endpoint
// fails closed. ConfigDir, when set, must name a new or protected empty
// directory.
type Options struct {
	Resolver          Resolver
	CommandRunner     CommandRunner
	EndpointValidator EndpointValidator
	ConfigDir         string
	Endpoint          Endpoint
}

// ProbeOptions supplies the explicit socket plus test seams for trusted
// endpoint onboarding. Ambient Docker configuration and credentials are never
// consulted.
type ProbeOptions struct {
	Resolver          Resolver
	CommandRunner     CommandRunner
	EndpointValidator EndpointValidator
	ConfigDir         string
	SocketPath        string
}

// Executor binds all of its invocations to one resolved Docker CLI and one
// empty, protected Docker configuration directory.
type Executor struct {
	options   Options
	once      sync.Once
	path      string
	env       []string
	err       error
	host      string
	configDir string

	verifyMu sync.Mutex
	verified bool
}

// New returns a lazily initialized executor. The first Path or Run call fixes
// the executable and environment for the lifetime of the executor.
func New(options Options) *Executor { return &Executor{options: options} }

// Probe inspects one explicit local Unix socket through the same isolated
// Docker boundary used by normal execution. Callers must present and confirm
// the returned identity before trusting or persisting it.
func Probe(ctx context.Context, socketPath string) (DaemonIdentity, error) {
	return ProbeWithOptions(ctx, ProbeOptions{SocketPath: socketPath})
}

// ProbeWithOptions is Probe with injectable process seams for tests.
func ProbeWithOptions(ctx context.Context, options ProbeOptions) (DaemonIdentity, error) {
	executor := New(Options{
		Resolver: options.Resolver, CommandRunner: options.CommandRunner,
		EndpointValidator: options.EndpointValidator, ConfigDir: options.ConfigDir,
		Endpoint: Endpoint{SocketPath: options.SocketPath},
	})
	if options.EndpointValidator == nil {
		executor.options.EndpointValidator = validateProbeEndpoint
	}
	executor.initialize()
	if executor.err != nil {
		return DaemonIdentity{}, executor.err
	}
	if options.ConfigDir == "" {
		defer func() { _ = os.RemoveAll(executor.configDir) }()
	}
	run := executor.options.CommandRunner
	if run == nil {
		run = runCommand
	}
	environment := append([]string(nil), executor.env...)
	sort.Strings(environment)
	probeCtx, cancel := context.WithTimeout(ctx, daemonProbeTimeout)
	defer cancel()
	return executor.probeDaemon(probeCtx, run, environment)
}

var (
	defaultMu       sync.RWMutex
	defaultExecutor Runner = New(Options{})
)

// Default returns the process-wide production executor.
func Default() Runner {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultExecutor
}

// ConfigureDefault replaces the fail-closed process default with an executor
// bound to endpoint. CLI entrypoints call it only after loading their reviewed
// configuration; ambient Docker variables are never consulted.
func ConfigureDefault(endpoint Endpoint) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultExecutor = New(Options{Endpoint: endpoint})
}

// Path returns the verified absolute Docker CLI path.
func (e *Executor) Path() (string, error) {
	e.initialize()
	return e.path, e.err
}

// Verify attests the configured daemon without running a caller command.
// Deploy entrypoints use it to fail before consuming deployment work.
func (e *Executor) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.initialize()
	if e.err != nil {
		return e.err
	}
	run := e.options.CommandRunner
	if run == nil {
		run = runCommand
	}
	environment := append([]string(nil), e.env...)
	sort.Strings(environment)
	probeCtx, cancel := context.WithTimeout(ctx, daemonProbeTimeout)
	defer cancel()
	if err := e.verifyDaemon(probeCtx, run, environment); err != nil {
		return &AttestationError{Err: err}
	}
	return nil
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
	baseEnvironment := append([]string(nil), e.env...)
	sort.Strings(baseEnvironment)
	environment := append([]string(nil), baseEnvironment...)
	for name, value := range request.Env {
		environment = append(environment, name+"="+value)
	}
	sort.Strings(environment)
	if err := e.Verify(ctx); err != nil {
		return Result{}, err
	}
	run := e.options.CommandRunner
	if run == nil {
		run = runCommand
	}
	request.Args = e.boundArgs(request.Args)
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

		validate := e.options.EndpointValidator
		if validate == nil {
			validate = validateEndpoint
		}
		socketPath, err := validate(e.options.Endpoint)
		if err != nil {
			e.err = err
			return
		}

		configDir, err := prepareConfigDir(e.options.ConfigDir)
		if err != nil {
			e.err = err
			return
		}
		e.path = path
		// Docker Desktop's macOS CLI needs a home directory even when an
		// explicit Unix socket and DOCKER_CONFIG are supplied. Without HOME it
		// can hang while probing `docker info`. Keep both HOME and TMPDIR inside
		// the same protected, credential-free directory instead of inheriting
		// either location from the caller.
		e.env = []string{
			"DOCKER_CONFIG=" + configDir,
			"HOME=" + configDir,
			"TMPDIR=" + configDir,
		}
		e.configDir = configDir
		e.host = "unix://" + filepath.ToSlash(socketPath)
	})
}

func (e *Executor) boundArgs(args []string) []string {
	bound := make([]string, 0, len(args)+2)
	bound = append(bound, "--host", e.host)
	return append(bound, args...)
}

type versionIdentity struct {
	ServerVersion   string `json:"server_version"`
	APIVersion      string `json:"api_version"`
	OperatingSystem string `json:"os"`
	Architecture    string `json:"architecture"`
}

type infoIdentity struct {
	ID              string   `json:"id"`
	SecurityOptions []string `json:"security_options"`
}

func (e *Executor) verifyDaemon(ctx context.Context, run CommandRunner, environment []string) error {
	e.verifyMu.Lock()
	defer e.verifyMu.Unlock()
	if e.verified {
		return nil
	}
	actual, err := e.probeDaemon(ctx, run, environment)
	if err != nil {
		return err
	}
	if err := attestDaemon(e.options.Endpoint.Expected, actual); err != nil {
		return err
	}
	e.verified = true
	return nil
}

func (e *Executor) probeDaemon(ctx context.Context, run CommandRunner, environment []string) (DaemonIdentity, error) {
	versionRequest := Request{
		Args:   e.boundArgs([]string{"version", "--format", `{"server_version":{{json .Server.Version}},"api_version":{{json .Server.APIVersion}},"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}}}`}),
		Stdout: Capture{Mode: Limit, Bytes: daemonOutputLimit},
		Stderr: Capture{Mode: Tail, Bytes: 4 << 10},
	}
	versionResult, err := run(ctx, e.path, versionRequest, environment)
	if err != nil {
		return DaemonIdentity{}, daemonProbeError(ctx, err)
	}
	var version versionIdentity
	if err := json.Unmarshal(versionResult.Stdout, &version); err != nil {
		return DaemonIdentity{}, errors.New("approved Docker daemon returned an invalid version identity")
	}
	infoRequest := Request{
		Args:   e.boundArgs([]string{"info", "--format", `{"id":{{json .ID}},"security_options":{{json .SecurityOptions}}}`}),
		Stdout: Capture{Mode: Limit, Bytes: daemonOutputLimit},
		Stderr: Capture{Mode: Tail, Bytes: 4 << 10},
	}
	infoResult, err := run(ctx, e.path, infoRequest, environment)
	if err != nil {
		return DaemonIdentity{}, daemonProbeError(ctx, err)
	}
	var info infoIdentity
	if err := json.Unmarshal(infoResult.Stdout, &info); err != nil {
		return DaemonIdentity{}, errors.New("approved Docker daemon returned an invalid capability identity")
	}
	architecture, err := NormalizeArchitecture(version.Architecture)
	if err != nil {
		return DaemonIdentity{}, err
	}
	securityOptions := append([]string(nil), info.SecurityOptions...)
	sort.Strings(securityOptions)
	actual := DaemonIdentity{
		ID: info.ID, ServerVersion: version.ServerVersion,
		OperatingSystem: version.OperatingSystem, Architecture: architecture,
		MinimumAPIVersion: version.APIVersion, RequiredSecurityOptions: securityOptions,
	}
	if err := validateExpectedIdentity(actual); err != nil {
		return DaemonIdentity{}, errors.New("approved Docker daemon returned an incomplete identity")
	}
	return actual, nil
}

func daemonProbeError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	category, _, _ := Classify(err)
	if category == safeerr.CategoryUnknown {
		return errors.New("approved Docker endpoint is inaccessible or does not support the required identity probe")
	}
	return fmt.Errorf("approved Docker endpoint identity probe failed (%s)", category)
}

func attestDaemon(expected, actual DaemonIdentity) error {
	if actual.ID != expected.ID {
		return errors.New("approved Docker daemon identity does not match docker configuration")
	}
	if actual.ServerVersion != expected.ServerVersion {
		return fmt.Errorf("approved Docker daemon server version is %q; expected %q", actual.ServerVersion, expected.ServerVersion)
	}
	expectedArchitecture, err := NormalizeArchitecture(expected.Architecture)
	if err != nil {
		return errors.New("approved Docker daemon architecture in configuration is unsupported")
	}
	if actual.OperatingSystem != expected.OperatingSystem || actual.Architecture != expectedArchitecture {
		return fmt.Errorf("approved Docker daemon platform is %s/%s; expected %s/%s", actual.OperatingSystem, actual.Architecture, expected.OperatingSystem, expectedArchitecture)
	}
	if compareAPIVersions(actual.MinimumAPIVersion, expected.MinimumAPIVersion) < 0 {
		return fmt.Errorf("approved Docker daemon API version is %q; version %q or newer is required", actual.MinimumAPIVersion, expected.MinimumAPIVersion)
	}
	available := make(map[string]bool, len(actual.RequiredSecurityOptions))
	for _, option := range actual.RequiredSecurityOptions {
		available[option] = true
	}
	for _, required := range expected.RequiredSecurityOptions {
		if !available[required] {
			return fmt.Errorf("approved Docker daemon is missing required security option %q", required)
		}
	}
	return nil
}

// NormalizeArchitecture maps Docker and kernel aliases to canonical OCI
// architecture names used by image platform requests.
func NormalizeArchitecture(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("docker daemon architecture %q is unsupported", value)
	}
}

func compareAPIVersions(actual, required string) int {
	parse := func(value string) (int, int, bool) {
		var major, minor int
		if _, err := fmt.Sscanf(value, "%d.%d", &major, &minor); err != nil || fmt.Sprintf("%d.%d", major, minor) != value {
			return 0, 0, false
		}
		return major, minor, true
	}
	actualMajor, actualMinor, actualOK := parse(actual)
	requiredMajor, requiredMinor, requiredOK := parse(required)
	if !actualOK || !requiredOK {
		return -1
	}
	if actualMajor != requiredMajor {
		if actualMajor > requiredMajor {
			return 1
		}
		return -1
	}
	if actualMinor > requiredMinor {
		return 1
	}
	if actualMinor < requiredMinor {
		return -1
	}
	return 0
}

func prepareConfigDir(path string) (string, error) {
	var err error
	if path == "" {
		path, err = os.MkdirTemp(dockerConfigTempRoot(runtime.GOOS), "vuelta-docker-config-")
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

func dockerConfigTempRoot(goos string) string {
	if goos == "darwin" {
		// Docker Desktop can hang when its isolated DOCKER_CONFIG lives under
		// DARWIN_USER_TEMP_DIR (/var/folders/...). A random 0700 directory in
		// macOS's private system temp root avoids that client bug without
		// exposing the caller's home or Docker credentials.
		return "/private/tmp"
	}
	return ""
}

func validateRequest(request Request) error {
	if len(request.Args) == 0 {
		return errors.New("docker argv is required")
	}
	if request.Combined.Mode != Discard && (request.Stdout.Mode != Discard || request.Stderr.Mode != Discard) {
		return errors.New("combined Docker capture cannot be mixed with stdout/stderr capture")
	}
	for _, capture := range []Capture{request.Stdout, request.Stderr, request.Combined} {
		if capture.Mode > Excerpt ||
			(capture.Mode != Discard && capture.Bytes <= 0) ||
			(capture.Mode == Excerpt && capture.Bytes <= 1) {
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
// arguments, environment values, or full child output. It still carries the
// exit code and a bounded, redacted diagnostic tail derived only from output
// the caller already chose to capture under its own limits.
type CommandError struct {
	err      error
	exitCode int
	detail   []byte
}

func (e *CommandError) Error() string { return "docker command failed" }
func (e *CommandError) Unwrap() error { return e.err }

// ExitCode returns the child's exit code, or -1 when it never ran to
// completion (for example, the executable could not be started).
func (e *CommandError) ExitCode() int { return e.exitCode }

// SafeDetail returns a bounded, redacted diagnostic excerpt safe for display.
func (e *CommandError) SafeDetail() string { return safeerr.Excerpt(e.detail, 1024) }

// Category derives a stable, safe failure classification from the bounded
// diagnostic tail already captured by the caller.
func (e *CommandError) Category() safeerr.Category { return safeerr.ClassifyDetail(e.SafeDetail()) }

// OutputLimitError reports which structured stream exceeded its hard cap.
type OutputLimitError struct {
	Stream string
	Limit  int
}

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("docker %s exceeded %d bytes", e.Stream, e.Limit)
}

// Classify derives a stable, safe category, exit code (-1 when unknown), and
// bounded redacted detail from an error returned by Run. It never inspects
// argv, environment, or unbounded output.
func Classify(err error) (safeerr.Category, int, string) {
	var limitErr *OutputLimitError
	if errors.As(err, &limitErr) {
		return safeerr.CategoryOutputLimit, -1, limitErr.Error()
	}
	var cmdErr *CommandError
	if errors.As(err, &cmdErr) {
		return cmdErr.Category(), cmdErr.ExitCode(), cmdErr.SafeDetail()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return safeerr.CategoryTimeout, -1, ""
	}
	if errors.Is(err, context.Canceled) {
		return safeerr.CategoryCancelled, -1, ""
	}
	return safeerr.CategoryUnknown, -1, ""
}

type collector struct {
	mode    CaptureMode
	limit   int
	tail    *capio.Tail
	excerpt *capio.Excerpt
	hard    *capio.Limit
}

func newCollector(capture Capture, cancel context.CancelFunc) *collector {
	c := &collector{mode: capture.Mode, limit: capture.Bytes}
	switch capture.Mode {
	case Tail:
		c.tail = capio.NewTail(capture.Bytes)
	case Limit:
		c.hard = capio.NewLimit(capture.Bytes, cancel)
	case Excerpt:
		c.excerpt = capio.NewExcerpt(capture.Bytes)
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
	if c.excerpt != nil {
		return c.excerpt
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
	if c.excerpt != nil {
		return []byte(c.excerpt.String())
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
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		detail := result.Stderr
		if len(detail) == 0 {
			detail = result.Combined
		}
		return result, &CommandError{err: err, exitCode: exitCode, detail: detail}
	}
	return result, nil
}
