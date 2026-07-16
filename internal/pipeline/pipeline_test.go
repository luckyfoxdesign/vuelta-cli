package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/testfixture"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
)

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newRepoWithRemote sets up a bare "remote" and the py-poetry-ok fixture,
// then pushes its initial commit to origin/main. This makes the pipeline
// integration tests exercise the same deterministic project used by local
// acceptance checks rather than an ad-hoc inline project.
func newRepoWithRemote(t *testing.T) (work string) {
	t.Helper()
	remote := t.TempDir()
	run(t, remote, "init", "-q", "--bare", "--initial-branch=main")

	work = t.TempDir()
	fixtures := filepath.Join("..", "..", "testdata", "fixtures", "projects")
	if err := testfixture.SetupProject(context.Background(), fixtures, "py-poetry-ok", work); err != nil {
		t.Fatal(err)
	}
	run(t, work, "remote", "add", "origin", remote)
	run(t, work, "push", "-q", "origin", "main")

	return work
}

func baseWorkspace(path string) config.Workspace {
	return config.Workspace{
		Path:           path,
		Stack:          config.StackPython,
		PackageManager: "poetry",
		Remote:         "origin",
		Branch:         "main",
		Test:           config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"},
	}
}

func baseConfig() config.Config {
	return config.Config{
		Git: config.GitConfig{AllowedChangedPaths: []string{"requirements.txt"}},
	}
}

// installFakeDocker puts a fake `docker` binary on PATH so scanner.CheckTools
// finds it and testrunner.Run's `docker compose run` succeeds/fails
// deterministically without a real daemon. passOnCall == 0 means always
// exit 0; passOnCall < 0 means always exit 1; passOnCall > 0 makes the
// script fail every call before the Nth and succeed from then on
// (simulating a test failure fixed by autofix).
func installFakeDocker(t *testing.T, passOnCall int) dockerexec.Runner {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	var script string
	switch {
	case passOnCall == 0:
		script = "#!/bin/sh\nexit 0\n"
	case passOnCall < 0:
		script = "#!/bin/sh\nexit 1\n"
	default:
		counter := filepath.Join(dir, "calls")
		if err := os.WriteFile(counter, []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
		script = fmt.Sprintf(`#!/bin/sh
n=$(/bin/cat %q)
n=$((n+1))
echo "$n" > %q
if [ "$n" -lt %d ]; then
  exit 1
fi
exit 0
`, counter, counter, passOnCall)
	}
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dockerexec.New(dockerexec.Options{Resolver: func(string) (string, error) { return path, nil }})
}

type fakeSecurityGate struct {
	baselineErr error
	postErr     error
}

func (f fakeSecurityGate) Baseline(context.Context, config.Workspace, config.Config) (Report, error) {
	return Report{Ran: true}, f.baselineErr
}

func (f fakeSecurityGate) PostCheck(context.Context, string, config.Workspace, config.Config, Report) (Report, error) {
	return Report{Ran: true, Findings: []string{"CVE-TEST-0001"}}, f.postErr
}

type fakeUpdater struct{ changed bool }

func (f fakeUpdater) Update(_ context.Context, projectPath string) (bool, error) {
	if !f.changed {
		return false, nil
	}
	return true, os.WriteFile(filepath.Join(projectPath, "requirements.txt"), []byte("flask==2.0.1\n"), 0o644)
}

type fakeAutofixer struct{ attempted bool }

func (f fakeAutofixer) Attempt(context.Context, string, string, string, config.AutofixConfig) (bool, error) {
	return f.attempted, nil
}

func fixedNow() time.Time { return time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC) }

func baseDeps(changed bool, docker dockerexec.Runner) Deps {
	return Deps{
		Sandbox:  BasicSandbox{},
		Security: fakeSecurityGate{},
		Autofix:  NotConfiguredAutofixer{},
		Now:      fixedNow,
		Docker:   docker,
		ResolveUpdater: func(config.Workspace, config.Config) (updater.Updater, error) {
			return fakeUpdater{changed: changed}, nil
		},
	}
}

func TestRunWorkspaceUpdatesAndPushesReviewBranch(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(true, docker)

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "updated" {
		t.Fatalf("expected status updated, got %+v", result)
	}
	wantBranch := "vuelta/deps/" + filepath.Base(work) + "-2026-07-13"
	if result.Branch != wantBranch {
		t.Fatalf("expected branch %q, got %q", wantBranch, result.Branch)
	}
	out := run(t, work, "ls-remote", "origin", "refs/heads/"+wantBranch)
	if strings.TrimSpace(out) == "" {
		t.Fatal("expected review branch to exist on remote")
	}
}

func TestRunWorkspaceSkipsWhenDirty(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	writeFile(t, work, "requirements.txt", "uncommitted change\n")
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(true, docker)

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "skipped" {
		t.Fatalf("expected status skipped, got %+v", result)
	}
}

func TestRunWorkspaceSkipsWhenNoChange(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(false, docker)

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "skipped" || result.Reason != "no dependency changes" {
		t.Fatalf("expected skipped/no dependency changes, got %+v", result)
	}
}

func TestRunWorkspaceFailsClosedOnSecurityBaselineError(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(true, docker)
	deps.Security = fakeSecurityGate{baselineErr: fmt.Errorf("trivy database unreachable")}

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "blocked" || result.Reason != "security baseline" {
		t.Fatalf("expected blocked/security baseline, got %+v", result)
	}
}

func TestRunWorkspaceRejectsDisallowedChange(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(true, docker)
	deps.ResolveUpdater = func(config.Workspace, config.Config) (updater.Updater, error) {
		return fakeUpdaterWritingFile{name: "README.md"}, nil
	}

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "failed" || !strings.Contains(result.Reason, "diff policy") {
		t.Fatalf("expected failed/diff policy, got %+v", result)
	}
}

type fakeUpdaterWritingFile struct{ name string }

func (f fakeUpdaterWritingFile) Update(_ context.Context, projectPath string) (bool, error) {
	return true, os.WriteFile(filepath.Join(projectPath, f.name), []byte("changed\n"), 0o644)
}

func TestRunWorkspaceDryRunSkipsCommitAndPush(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(true, docker)

	result := RunWorkspace(context.Background(), deps, cfg, ws, true)
	if result.Status != "dry_run" {
		t.Fatalf("expected status dry_run, got %+v", result)
	}
	out := run(t, work, "branch", "-r")
	if strings.Contains(out, "vuelta/deps/") {
		t.Fatalf("dry-run must not push a review branch, remote branches: %s", out)
	}
}

func TestRunWorkspaceTestFailureNoAutofix(t *testing.T) {
	docker := installFakeDocker(t, -1) // never passes
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	deps := baseDeps(true, docker)

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "failed" || result.Reason != "tests failed" {
		t.Fatalf("expected failed/tests failed, got %+v", result)
	}
}

func TestRunWorkspaceAutofixSucceedsPushesAutofixBranch(t *testing.T) {
	docker := installFakeDocker(t, 2) // fails first call, passes from the second
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	cfg.Autofix.Enabled = true
	deps := baseDeps(true, docker)
	deps.Autofix = fakeAutofixer{attempted: true}

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "updated" {
		t.Fatalf("expected status updated after autofix, got %+v", result)
	}
	if !result.AutofixApplied {
		t.Fatalf("expected successful autofix to be recorded, got %+v", result)
	}
	wantBranch := "vuelta/autofix/" + filepath.Base(work) + "-2026-07-13"
	if result.Branch != wantBranch {
		t.Fatalf("expected autofix branch %q, got %q", wantBranch, result.Branch)
	}
	out := run(t, work, "ls-remote", "origin", "refs/heads/"+wantBranch)
	if strings.TrimSpace(out) == "" {
		t.Fatal("expected autofix branch to exist on remote")
	}
}

func TestRunWorkspaceDryRunAutofixDoesNotCommitOrPush(t *testing.T) {
	docker := installFakeDocker(t, 2) // fails first call, passes after autofix
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	cfg.Autofix.Enabled = true
	deps := baseDeps(true, docker)
	deps.Autofix = fakeAutofixer{attempted: true}

	beforeHead := strings.TrimSpace(run(t, work, "rev-parse", "HEAD"))
	beforeRemoteRefs := run(t, work, "ls-remote", "origin")

	result := RunWorkspace(context.Background(), deps, cfg, ws, true)
	if result.Status != "dry_run" || !result.AutofixApplied {
		t.Fatalf("expected dry_run with autofix applied, got %+v", result)
	}
	if got := strings.TrimSpace(run(t, work, "rev-parse", "HEAD")); got != beforeHead {
		t.Fatalf("dry-run must not create a commit in the workspace: got HEAD %s, want %s", got, beforeHead)
	}
	if got := run(t, work, "ls-remote", "origin"); got != beforeRemoteRefs {
		t.Fatalf("dry-run must not change remote refs: got %q, want %q", got, beforeRemoteRefs)
	}
	remoteRefs := run(t, work, "ls-remote", "origin", "refs/heads/vuelta/deps/*", "refs/heads/vuelta/autofix/*")
	if strings.TrimSpace(remoteRefs) != "" {
		t.Fatalf("dry-run must not push review refs, got: %s", remoteRefs)
	}
}

func TestRunWorkspaceAutofixStillFails(t *testing.T) {
	docker := installFakeDocker(t, -1) // never passes, even after "autofix"
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	cfg.Autofix.Enabled = true
	deps := baseDeps(true, docker)
	deps.Autofix = fakeAutofixer{attempted: true}

	result := RunWorkspace(context.Background(), deps, cfg, ws, false)
	if result.Status != "failed" || result.Reason != "tests failed" {
		t.Fatalf("expected failed/tests failed, got %+v", result)
	}
}

func TestRunAggregatesResultsUnderLock(t *testing.T) {
	docker := installFakeDocker(t, 0)
	work := newRepoWithRemote(t)
	ws := baseWorkspace(work)
	cfg := baseConfig()
	cfg.Workspaces = []config.Workspace{ws}
	deps := baseDeps(true, docker)

	lockPath := filepath.Join(t.TempDir(), "vuelta.lock")
	summary, err := Run(context.Background(), deps, cfg, lockPath, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(summary.Results) != 1 || summary.Results[0].Status != "updated" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	updated, skipped, failed := summary.Counts()
	if updated != 1 || skipped != 0 || failed != 0 {
		t.Fatalf("unexpected counts: updated=%d skipped=%d failed=%d", updated, skipped, failed)
	}
}

func TestRunFailsWhenLockAlreadyHeld(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "vuelta.lock")
	held, err := AcquireProcessLock(lockPath)
	if err != nil {
		t.Fatalf("AcquireProcessLock: %v", err)
	}
	defer func() { _ = held.Release() }()

	cfg := baseConfig()
	deps := baseDeps(true, nil)
	if _, err := Run(context.Background(), deps, cfg, lockPath, false); err == nil {
		t.Fatal("expected Run to fail while the lock is already held")
	}
}
