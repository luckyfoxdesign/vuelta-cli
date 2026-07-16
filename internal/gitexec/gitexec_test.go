package gitexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	base := filepath.Base(os.Args[0])
	if base == "post-checkout" || base == "fsmonitor-helper" || base == "diff-helper" {
		_ = os.WriteFile(filepath.Join(filepath.Dir(os.Args[0]), base+".marker"), []byte("executed\n"), 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testExecutable(t *testing.T, name string) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func systemGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func testRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	systemGit(t, dir, "init", "-q")
	systemGit(t, dir, "config", "user.name", "test")
	systemGit(t, dir, "config", "user.email", "test@example.invalid")
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	systemGit(t, dir, "add", "tracked.txt")
	systemGit(t, dir, "commit", "-q", "-m", "initial")
	return dir
}

func TestExecutorBindsApprovedPathAndDropsHostileEnvironment(t *testing.T) {
	approved := testExecutable(t, "git")
	stateDir := filepath.Join(t.TempDir(), "state")
	var gotPath string
	var gotArgs, gotEnv []string
	executor := New(Options{
		CandidatePaths: []string{approved},
		StateDir:       stateDir,
		CommandRunner: func(_ context.Context, path string, _ Request, args, env []string) (Result, error) {
			gotPath = path
			gotArgs = append([]string(nil), args...)
			gotEnv = append([]string(nil), env...)
			return Result{}, nil
		},
	})
	for name, value := range map[string]string{
		"PATH": "/hostile/bin", "HOME": "/hostile/home",
		"GIT_CONFIG_SYSTEM": "/hostile/system", "GIT_CONFIG_GLOBAL": "/hostile/global",
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
		"GIT_CONFIG_VALUE_0": "/hostile/helper", "GIT_SSH": "/hostile/ssh",
		"GIT_SSH_COMMAND": "/hostile/ssh --option", "GIT_ASKPASS": "/hostile/askpass",
		"GIT_EXTERNAL_DIFF": "/hostile/diff", "SSH_ASKPASS": "/hostile/askpass",
	} {
		t.Setenv(name, value)
	}
	if _, err := executor.Run(context.Background(), Request{Args: []string{"ls-files"}, Dir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.EvalSymlinks(approved)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != wantPath {
		t.Fatalf("path = %q, want %q", gotPath, wantPath)
	}
	joinedEnv := strings.Join(gotEnv, "\n")
	if strings.Contains(joinedEnv, "/hostile/") || strings.Contains(joinedEnv, "GIT_SSH") {
		t.Fatalf("hostile environment reached child: %q", gotEnv)
	}
	for _, required := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "PATH=/usr/bin:/bin"} {
		if !contains(gotEnv, required) {
			t.Fatalf("child environment missing %q: %q", required, gotEnv)
		}
	}
	if !contains(gotArgs, "ls-files") || configValue(gotEnv, "core.fsmonitor") != "false" || configValue(gotEnv, "credential.helper") != "" {
		t.Fatalf("hardened Git config missing from environment: %q", gotEnv)
	}
}

func TestExecutorIgnoresRepositoryHooksAndHelpers(t *testing.T) {
	repo := testRepo(t)
	hooks := t.TempDir()
	postCheckout := testExecutableAt(t, hooks, "post-checkout")
	fsmonitor := testExecutableAt(t, hooks, "fsmonitor-helper")
	diff := testExecutableAt(t, hooks, "diff-helper")
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("tracked.txt filter=owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	systemGit(t, repo, "add", "tracked.txt", ".gitattributes")
	systemGit(t, repo, "commit", "-q", "-m", "second")
	systemGit(t, repo, "config", "core.hooksPath", hooks)
	systemGit(t, repo, "config", "core.fsmonitor", fsmonitor)
	systemGit(t, repo, "config", "diff.external", diff)
	systemGit(t, repo, "config", "filter.owned.clean", fsmonitor)
	systemGit(t, repo, "config", "filter.owned.required", "true")

	for name, value := range map[string]string{
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": hooks,
		"GIT_EXTERNAL_DIFF": diff, "GIT_SSH_COMMAND": postCheckout,
	} {
		t.Setenv(name, value)
	}
	if _, err := Output(context.Background(), repo, "ls-files", "-z"); err != nil {
		t.Fatalf("ls-files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(systemGit(t, repo, "rev-parse", "HEAD"))
	changes, err := InspectWorktree(context.Background(), repo, sha)
	if err != nil {
		t.Fatalf("InspectWorktree: %v", err)
	}
	if len(changes) != 1 || changes[0].Path != "tracked.txt" {
		t.Fatalf("InspectWorktree changes = %#v", changes)
	}
	if _, err := Output(context.Background(), repo, "diff-tree", "-p", "--no-ext-diff", "--no-textconv", "HEAD^", "HEAD", "--"); err != nil {
		t.Fatalf("diff-tree: %v", err)
	}
	landing := filepath.Join(t.TempDir(), "landing")
	if _, err := Output(context.Background(), repo, "worktree", "add", "--no-checkout", "--detach", landing, sha); err != nil {
		t.Fatalf("worktree add: %v", err)
	}
	t.Cleanup(func() { _, _ = Output(context.Background(), repo, "worktree", "remove", "--force", landing) })
	for _, helper := range []string{postCheckout, fsmonitor, diff} {
		marker := filepath.Join(filepath.Dir(helper), filepath.Base(helper)+".marker")
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("repository-controlled helper executed: %s", marker)
		}
	}
}

func TestExecutorRejectsHostileRequestValues(t *testing.T) {
	executor := New(Options{CandidatePaths: []string{testExecutable(t, "git")}, StateDir: filepath.Join(t.TempDir(), "state")})
	for _, request := range []Request{
		{Args: []string{"clone", "https://example.invalid/repo"}, Dir: t.TempDir()},
		{Args: []string{"ls-files"}, Dir: "relative"},
		{Args: []string{"ls-files"}, Dir: t.TempDir(), Env: map[string]string{"GIT_SSH_COMMAND": "/tmp/helper"}},
	} {
		if _, err := executor.Run(context.Background(), request); err == nil {
			t.Fatalf("request unexpectedly accepted: %#v", request)
		}
	}
	for _, value := range []string{"-origin", "ext::helper", "ssh://host/repo", "origin/main"} {
		if err := ValidateRemoteName(value); err == nil {
			t.Fatalf("remote %q unexpectedly accepted", value)
		}
	}
	for _, value := range []string{"-branch", "main..next", "refs/heads/main", "main.lock", "main~1"} {
		if err := ValidateBranch(value); err == nil {
			t.Fatalf("branch %q unexpectedly accepted", value)
		}
	}
	if !reflect.DeepEqual([]error{ValidateRemoteName("origin"), ValidateBranch("feature/safe")}, []error{nil, nil}) {
		t.Fatal("safe remote/ref rejected")
	}
}

func TestUnsafeRemoteFailsBeforeTransportCommand(t *testing.T) {
	calls := 0
	executor := New(Options{
		CandidatePaths: []string{testExecutable(t, "git")},
		StateDir:       filepath.Join(t.TempDir(), "state"),
		CommandRunner: func(_ context.Context, _ string, request Request, _, _ []string) (Result, error) {
			calls++
			if len(request.Args) == 0 || request.Args[0] != "remote" {
				t.Fatalf("transport command started for unsafe remote: %#v", request.Args)
			}
			return Result{Output: []byte("ext::unapproved-helper\n")}, nil
		},
	})
	_, err := executor.Run(context.Background(), Request{Args: []string{"fetch", "--prune", "origin"}, Dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "transport") {
		t.Fatalf("unsafe remote error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("command runner calls = %d, want remote lookup only", calls)
	}
}

func testExecutableAt(t *testing.T, dir, name string) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func configValue(environment []string, wantKey string) string {
	values := make(map[string]string)
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			values[name] = value
		}
	}
	for i := 0; ; i++ {
		key, ok := values[fmt.Sprintf("GIT_CONFIG_KEY_%d", i)]
		if !ok {
			return ""
		}
		if key == wantKey {
			return values[fmt.Sprintf("GIT_CONFIG_VALUE_%d", i)]
		}
	}
}
