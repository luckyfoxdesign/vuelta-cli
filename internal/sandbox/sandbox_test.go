package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/testfixture"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func repo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	git(t, dir, "config", "user.email", "test@example.invalid")
	git(t, dir, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("not copied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("not copied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "tracked.txt")
	git(t, dir, "commit", "-q", "-m", "initial")
	return dir, strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
}

func TestPrepareArchivesOnlyTrackedBaseFiles(t *testing.T) {
	repoPath, sha := repo(t)
	dir, cleanup, err := Prepare(context.Background(), repoPath, sha)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	if data, err := os.ReadFile(filepath.Join(dir, "tracked.txt")); err != nil || string(data) != "tracked\n" {
		t.Fatalf("tracked file: %q, %v", data, err)
	}
	for _, name := range []string{".git", ".env", "untracked.txt"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("sandbox unexpectedly contains %s: %v", name, err)
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("sandbox mode = %o, want 700", info.Mode().Perm())
	}
}

func TestPrepareRejectsSymlinkedProjectPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	repoPath, sha := repo(t)
	link := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(repoPath, link); err != nil {
		t.Fatal(err)
	}
	_, _, err := Prepare(context.Background(), link, sha)
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("expected canonical-path rejection, got %v", err)
	}
}

func TestPrepareCleansUpOnInvalidRevision(t *testing.T) {
	repoPath, _ := repo(t)
	_, _, err := Prepare(context.Background(), repoPath, "not-a-sha")
	if err == nil || !strings.Contains(err.Error(), "verify base SHA") {
		t.Fatalf("expected invalid revision error, got %v", err)
	}
}

func TestMaliciousFixtureSandboxExcludesGitAndHostState(t *testing.T) {
	repoPath := filepath.Join(t.TempDir(), "malicious-postinstall")
	fixtures := filepath.Join("..", "..", "testdata", "fixtures", "projects")
	if err := testfixture.SetupProject(context.Background(), fixtures, "malicious-postinstall", repoPath); err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(git(t, repoPath, "rev-parse", "HEAD"))
	sandboxPath, cleanup, err := Prepare(context.Background(), repoPath, sha)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })

	if _, err := os.Stat(filepath.Join(sandboxPath, "postinstall.sh")); err != nil {
		t.Fatalf("fixture install script must be present for sandbox testing: %v", err)
	}
	for _, forbidden := range []string{".git", ".env"} {
		if _, err := os.Lstat(filepath.Join(sandboxPath, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("sandbox unexpectedly exposes %s: %v", forbidden, err)
		}
	}
}

func TestEscapeSymlinkFixtureDoesNotEnterSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture requires a POSIX filesystem")
	}
	repoPath := filepath.Join(t.TempDir(), "escape-symlink")
	fixtures := filepath.Join("..", "..", "testdata", "fixtures", "projects")
	if err := testfixture.SetupProject(context.Background(), fixtures, "escape-symlink", repoPath); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repoPath, "outside-link")); err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(git(t, repoPath, "rev-parse", "HEAD"))
	sandboxPath, cleanup, err := Prepare(context.Background(), repoPath, sha)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	if _, err := os.Lstat(filepath.Join(sandboxPath, "outside-link")); !os.IsNotExist(err) {
		t.Fatalf("untracked symlink unexpectedly entered sandbox: %v", err)
	}
}
