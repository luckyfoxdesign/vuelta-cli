// Package gitexec is the single process boundary for production Git commands.
//
// Security invariants:
//   - the executable is selected only from compiled-in absolute system paths;
//   - children receive a small explicit environment, never the caller's Git,
//     askpass, proxy, or executable-selection variables;
//   - system/global config, hooks, fsmonitor, credential helpers, external
//     diff, automatic maintenance, signing, and unsafe protocols are disabled;
//   - callers may run only the reviewed command set and may add only a private
//     absolute GIT_INDEX_FILE.
//
// Repository data and ordinary non-executable repository configuration remain
// visible to Git. Callers must still validate remote names, refs, and paths at
// their own trust boundary before placing them in argv.
package gitexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
)

const (
	defaultOutputLimit = 16 << 20
	defaultWaitDelay   = 10 * time.Second
)

var allowedCommands = map[string]bool{
	"archive": true, "branch": true, "commit-tree": true, "diff-index": true, "diff-tree": true,
	"fetch": true, "for-each-ref": true, "hash-object": true,
	"init": true, "ls-files": true, "ls-remote": true, "ls-tree": true,
	"merge-base": true, "push": true, "read-tree": true, "remote": true,
	"rev-parse": true, "update-index": true,
	"tag": true, "update-ref": true, "verify-tag": true, "worktree": true,
	"write-tree": true,
}

// Request describes one Git invocation. Args excludes the executable name.
// When Stdout is nil, stdout and stderr are captured together with a hard
// limit. When Stdout is set, stdout is streamed and only a bounded stderr tail
// is retained for failure diagnostics.
type Request struct {
	Args      []string
	Dir       string
	Env       map[string]string
	Stdout    io.Writer
	WaitDelay time.Duration
}

// Result contains bounded output. Output is combined output unless Request
// supplied Stdout, in which case it contains only the diagnostic stderr tail.
type Result struct{ Output []byte }

// Runner is the shared Git execution interface used by production packages.
type Runner interface {
	Path() (string, error)
	Run(context.Context, Request) (Result, error)
}

// CommandRunner is a test seam around the already-approved executable.
type CommandRunner func(context.Context, string, Request, []string, []string) (Result, error)

// Options supplies test seams. CandidatePaths must contain absolute paths.
type Options struct {
	CandidatePaths []string
	CommandRunner  CommandRunner
	StateDir       string
}

// Executor binds all commands to one approved Git executable and one isolated
// configuration state directory.
type Executor struct {
	options Options
	once    sync.Once
	path    string
	env     []string
	prefix  []string
	err     error
}

// New returns a lazily initialized hardened executor.
func New(options Options) *Executor { return &Executor{options: options} }

var defaultExecutor Runner = New(Options{})

// Default returns the process-wide production executor.
func Default() Runner { return defaultExecutor }

// Output runs a command with the default executor and returns its bounded
// combined output.
func Output(ctx context.Context, dir string, args ...string) ([]byte, error) {
	result, err := Default().Run(ctx, Request{Args: args, Dir: dir})
	return result.Output, err
}

// OutputWithIndex is Output with one private absolute Git index file.
func OutputWithIndex(ctx context.Context, dir, indexFile string, args ...string) ([]byte, error) {
	result, err := Default().Run(ctx, Request{
		Args: args, Dir: dir, Env: map[string]string{"GIT_INDEX_FILE": indexFile},
	})
	return result.Output, err
}

// Path returns the approved absolute Git executable path.
func (e *Executor) Path() (string, error) {
	e.initialize()
	return e.path, e.err
}

// Run executes one reviewed Git command with the fixed binary and environment.
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
	args := append(append([]string(nil), e.prefix...), request.Args...)
	var err error
	args, err = e.hardenNetworkCommand(ctx, request, args, environment, run)
	if err != nil {
		return Result{}, err
	}
	return run(ctx, e.path, request, args, environment)
}

func (e *Executor) hardenNetworkCommand(ctx context.Context, request Request, args, environment []string, run CommandRunner) ([]string, error) {
	remote, push, ok := networkRemote(request.Args)
	if !ok {
		return args, nil
	}
	if err := ValidateRemoteName(remote); err != nil {
		return nil, err
	}
	lookup := append(append([]string(nil), e.prefix...), "remote", "get-url")
	if push {
		lookup = append(lookup, "--push")
	}
	lookup = append(lookup, remote)
	result, err := run(ctx, e.path, Request{Args: []string{"remote", "get-url"}, Dir: request.Dir}, lookup, environment)
	if err != nil {
		return nil, errors.New("resolve validated Git remote URL")
	}
	local, err := validateRemoteURL(strings.TrimSpace(string(result.Output)))
	if err != nil {
		return nil, err
	}
	if !local {
		return args, nil
	}
	commandIndex := len(e.prefix)
	command := "upload-pack"
	optionName := "--upload-pack="
	if push {
		command = "receive-pack"
		optionName = "--receive-pack="
	}
	nested := optionName + e.path + " -c core.hooksPath=/nonexistent/vuelta-hooks -c gc.auto=0 " + command
	hardened := make([]string, 0, len(args)+1)
	hardened = append(hardened, args[:commandIndex+1]...)
	hardened = append(hardened, nested)
	hardened = append(hardened, args[commandIndex+1:]...)
	return hardened, nil
}

func networkRemote(args []string) (remote string, push, ok bool) {
	if len(args) < 2 || (args[0] != "fetch" && args[0] != "push" && args[0] != "ls-remote") {
		return "", false, false
	}
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg, args[0] == "push", true
	}
	return "", false, false

}

func validateRemoteURL(raw string) (bool, error) {
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return false, errors.New("git remote URL is invalid")
	}
	if filepath.IsAbs(raw) {
		return true, nil
	}
	u, err := url.Parse(raw)
	if err == nil && u.Scheme != "" {
		switch u.Scheme {
		case "file":
			if u.User != nil || (u.Host != "" && u.Host != "localhost") || !filepath.IsAbs(u.Path) {
				return false, errors.New("git file remote URL is invalid")
			}
			return true, nil
		case "https":
			if u.User != nil || u.Hostname() == "" {
				return false, errors.New("git HTTPS remote URL is invalid")
			}
			return false, nil
		case "ssh":
			if u.Hostname() == "" {
				return false, errors.New("git SSH remote URL is invalid")
			}
			return false, nil
		default:
			return false, errors.New("git remote transport is not allowed")
		}
	}
	colon := strings.IndexByte(raw, ':')
	if colon > 0 && colon < len(raw)-1 && !strings.ContainsAny(raw[:colon], "/\\ \t") && !strings.ContainsAny(raw[colon+1:], " \t\r\n") {
		return false, nil
	}
	return false, errors.New("git remote URL must use file, HTTPS, or SSH transport")
}

func (e *Executor) initialize() {
	e.once.Do(func() {
		candidates := e.options.CandidatePaths
		if len(candidates) == 0 {
			candidates = defaultCandidates("git")
		}
		path, err := selectExecutable(candidates, "Git")
		if err != nil {
			e.err = err
			return
		}
		stateDir, err := prepareStateDir(e.options.StateDir)
		if err != nil {
			e.err = err
			return
		}
		home := stateDir
		if current, currentErr := user.Current(); currentErr == nil && filepath.IsAbs(current.HomeDir) {
			home = current.HomeDir
		}
		ssh := firstUsable(defaultCandidates("ssh"))
		if ssh == "" {
			ssh = filepath.Join(stateDir, "unavailable-ssh")
		}
		gpg := firstUsable(defaultCandidates("gpg"))
		if gpg == "" {
			gpg = filepath.Join(stateDir, "unavailable-gpg")
		}

		e.path = path
		e.env = []string{
			"GIT_ATTR_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=" + filepath.Join(stateDir, "global.gitconfig"),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
			"HOME=" + home,
			"LANG=C",
			"LC_ALL=C",
			"PATH=/usr/bin:/bin",
			// Avoid macOS confstr(DARWIN_USER_TEMP_DIR) warnings entering the
			// bounded combined output consumed by metadata-only callers.
			"TMPDIR=" + stateDir,
		}
		if socket := approvedAgentSocket(); socket != "" {
			e.env = append(e.env, "SSH_AUTH_SOCK="+socket)
		}
		configs := []string{
			"core.hooksPath=" + filepath.Join(stateDir, "hooks"),
			"core.fsmonitor=false",
			"core.untrackedCache=false",
			"core.excludesFile=" + filepath.Join(stateDir, "exclude"),
			"core.sshCommand=" + ssh,
			"core.askPass=",
			"credential.helper=",
			"diff.external=",
			"interactive.diffFilter=",
			"commit.gpgSign=false",
			"tag.gpgSign=false",
			"gpg.program=" + gpg,
			"gc.auto=0",
			"maintenance.auto=false",
			"fetch.recurseSubmodules=false",
			"submodule.recurse=false",
			"http.proxy=",
			"protocol.allow=never",
			"protocol.file.allow=always",
			"protocol.https.allow=always",
			"protocol.ssh.allow=always",
			"protocol.git.allow=never",
			"protocol.ext.allow=never",
		}
		e.prefix = []string{"--no-pager", "--no-optional-locks"}
		e.env = append(e.env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(configs)))
		for i, value := range configs {
			key, configValue, _ := strings.Cut(value, "=")
			e.env = append(e.env,
				fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, key),
				fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, configValue),
			)
		}
	})
}

func defaultCandidates(tool string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/usr/bin/" + tool}
	case "linux":
		return []string{"/usr/bin/" + tool, "/bin/" + tool}
	default:
		return nil
	}
}

func selectExecutable(candidates []string, label string) (string, error) {
	for _, candidate := range candidates {
		if !filepath.IsAbs(candidate) {
			return "", fmt.Errorf("approved %s candidate must be absolute", label)
		}
		path, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		if err := validateOwner(info); err != nil {
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("no approved absolute %s executable is available", label)
}

func firstUsable(candidates []string) string {
	path, _ := selectExecutable(candidates, "helper")
	return path
}

func prepareStateDir(path string) (string, error) {
	var err error
	if path == "" {
		path, err = os.MkdirTemp("", "vuelta-git-state-")
	} else {
		err = os.Mkdir(path, 0o700)
		if os.IsExist(err) {
			err = nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("create isolated Git state: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("isolated Git state must be a 0700 directory")
	}
	if err := os.Mkdir(filepath.Join(path, "hooks"), 0o700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create empty Git hooks directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(path, "global.gitconfig"), nil, 0o600); err != nil {
		return "", fmt.Errorf("create empty global Git config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(path, "exclude"), nil, 0o600); err != nil {
		return "", fmt.Errorf("create empty global Git excludes file: %w", err)
	}
	return path, nil
}

func approvedAgentSocket() string {
	value := os.Getenv("SSH_AUTH_SOCK")
	if !filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return ""
	}
	info, err := os.Stat(value)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return ""
	}
	return value
}

func validateRequest(request Request) error {
	if len(request.Args) == 0 || !allowedCommands[request.Args[0]] {
		return errors.New("git command is not allowlisted")
	}
	if request.Dir == "" || !filepath.IsAbs(request.Dir) {
		return errors.New("git working directory must be absolute")
	}
	for _, arg := range request.Args {
		if strings.ContainsRune(arg, '\x00') {
			return errors.New("git argument contains NUL")
		}
	}
	for name, value := range request.Env {
		if name != "GIT_INDEX_FILE" || !filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
			return errors.New("git environment is not allowlisted")
		}
	}
	return nil
}

// CommandError reports a Git failure without exposing untrusted argv or env.
type CommandError struct{ err error }

func (e *CommandError) Error() string { return "git command failed" }
func (e *CommandError) Unwrap() error { return e.err }

func runCommand(ctx context.Context, path string, request Request, args, environment []string) (Result, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, path, args...)
	cmd.Dir = request.Dir
	cmd.Env = environment
	cmd.WaitDelay = request.WaitDelay
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = defaultWaitDelay
	}
	var output io.Writer
	var hard *capio.Limit
	var tail *capio.Tail
	if request.Stdout == nil {
		hard = capio.NewLimit(defaultOutputLimit, cancel)
		output = hard
		cmd.Stdout = output
		cmd.Stderr = output
	} else {
		tail = capio.NewTail(64 << 10)
		cmd.Stdout = request.Stdout
		cmd.Stderr = tail
	}
	err := cmd.Run()
	var result Result
	if hard != nil {
		result.Output = hard.Bytes()
		if hard.Exceeded() {
			return result, errors.New("git output exceeded limit")
		}
	} else {
		result.Output = []byte(tail.String())
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		return result, &CommandError{err: err}
	}
	return result, nil
}
