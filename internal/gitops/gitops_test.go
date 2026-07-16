package gitops

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
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

// newRepoWithRemote creates a bare "remote" repo and a working clone with
// origin/main pointing at an initial commit. It returns the working repo
// path.
func newRepoWithRemote(t *testing.T) string {
	t.Helper()
	remote := t.TempDir()
	run(t, remote, "init", "-q", "--bare", "--initial-branch=main")

	work := t.TempDir()
	run(t, work, "init", "-q", "--initial-branch=main")
	run(t, work, "config", "user.email", "test@example.com")
	run(t, work, "config", "user.name", "test")
	run(t, work, "remote", "add", "origin", remote)

	writeFile(t, work, "requirements.txt", "flask==2.0.0\n")
	writeFile(t, work, "README.md", "hello\n")
	run(t, work, "add", "-A")
	run(t, work, "commit", "-q", "-m", "init")
	run(t, work, "push", "-q", "origin", "main")

	return work
}

func TestFetchAndBaseSHA(t *testing.T) {
	work := newRepoWithRemote(t)
	sha, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}
	if sha == "" {
		t.Fatal("expected non-empty SHA")
	}
	head := strings.TrimSpace(run(t, work, "rev-parse", "HEAD"))
	if sha != head {
		t.Fatalf("expected base SHA %s to equal local HEAD %s", sha, head)
	}
}

func TestRunGitHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := runGit(ctx, t.TempDir(), "status", "--porcelain")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestLandingCleanupUsesBoundedContextAfterParentCancellation(t *testing.T) {
	work := newRepoWithRemote(t)
	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	landing, cleanup, err := NewLandingCopy(ctx, work, baseSHA)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup after cancellation: %v", err)
	}
	if _, err := os.Stat(landing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("landing copy still exists after cleanup: %v", err)
	}
}

func TestVerifyBaseSHAUnchangedDetectsDrift(t *testing.T) {
	work := newRepoWithRemote(t)
	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}

	if err := VerifyBaseSHAUnchanged(context.Background(), work, "origin", "main", baseSHA); err != nil {
		t.Fatalf("expected no drift yet: %v", err)
	}

	// A second clone pushes a new commit to the same remote branch.
	remoteURL := strings.TrimSpace(run(t, work, "remote", "get-url", "origin"))
	other := t.TempDir()
	run(t, other, "clone", "-q", remoteURL, ".")
	run(t, other, "config", "user.email", "test@example.com")
	run(t, other, "config", "user.name", "test")
	writeFile(t, other, "requirements.txt", "flask==2.0.1\n")
	run(t, other, "add", "-A")
	run(t, other, "commit", "-q", "-m", "concurrent update")
	run(t, other, "push", "-q", "origin", "main")

	if err := VerifyBaseSHAUnchanged(context.Background(), work, "origin", "main", baseSHA); err == nil {
		t.Fatal("expected drift to be detected")
	}
}

func TestLandingCopySyncAndDiffCheck(t *testing.T) {
	work := newRepoWithRemote(t)
	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}

	landing, cleanup, err := NewLandingCopy(context.Background(), work, baseSHA)
	if err != nil {
		t.Fatalf("NewLandingCopy: %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	sandbox := t.TempDir()
	writeFile(t, sandbox, "requirements.txt", "flask==2.0.1\n")
	writeFile(t, sandbox, "README.md", "hello\n") // unchanged

	if err := SyncTree(sandbox, landing); err != nil {
		t.Fatalf("SyncTree: %v", err)
	}

	if err := DiffCheck(context.Background(), landing, []string{"requirements.txt"}); err != nil {
		t.Fatalf("DiffCheck: %v", err)
	}
}

func TestDiffCheckRejectsDisallowedPath(t *testing.T) {
	work := newRepoWithRemote(t)
	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}
	landing, cleanup, err := NewLandingCopy(context.Background(), work, baseSHA)
	if err != nil {
		t.Fatalf("NewLandingCopy: %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	writeFile(t, landing, "README.md", "changed\n")

	if err := DiffCheck(context.Background(), landing, []string{"requirements.txt"}); err == nil {
		t.Fatal("expected DiffCheck to reject a non-allowlisted change")
	}
}

func TestPathAllowedUsesRepositoryRelativePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{name: "root exact", path: "package.json", patterns: []string{"package.json"}, want: true},
		{name: "root exact rejects nested", path: "nested/package.json", patterns: []string{"package.json"}},
		{name: "nested exact", path: "nested/package.json", patterns: []string{"nested/package.json"}, want: true},
		{name: "nested glob", path: "nested/package.json", patterns: []string{"nested/*.json"}, want: true},
		{name: "glob does not cross slash", path: "nested/deeper/package.json", patterns: []string{"nested/*.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathAllowed(tt.path, tt.patterns); got != tt.want {
				t.Fatalf("pathAllowed(%q, %q) = %v, want %v", tt.path, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestDiffCheckRootPatternRejectsNestedSameBasename(t *testing.T) {
	work := newRepoWithRemote(t)
	writeFile(t, work, "nested/package.json", "{}\n")

	if err := DiffCheck(context.Background(), work, []string{"package.json"}); err == nil {
		t.Fatal("expected root-only package.json pattern to reject nested/package.json")
	}
	if err := DiffCheck(context.Background(), work, []string{"nested/*.json"}); err != nil {
		t.Fatalf("explicit nested glob should allow the path: %v", err)
	}
}

func TestNULDelimitedPathParsingPreservesQuotedAndNewlinePath(t *testing.T) {
	t.Parallel()
	path := "deps/\n\"quoted\".lock"
	changes, err := parsePorcelainStatus("?? " + path + "\x00")
	if err != nil {
		t.Fatalf("parsePorcelainStatus: %v", err)
	}
	if len(changes) != 1 || changes[0].path != path {
		t.Fatalf("changes = %#v, want exact path %q", changes, path)
	}
	if _, err := parsePorcelainStatus("?? " + path); err == nil {
		t.Fatal("expected non-NUL-terminated status to fail closed")
	}
}

func TestDiffCheckRejectsSymlink(t *testing.T) {
	work := newRepoWithRemote(t)
	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}
	landing, cleanup, err := NewLandingCopy(context.Background(), work, baseSHA)
	if err != nil {
		t.Fatalf("NewLandingCopy: %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	if err := os.Symlink("/etc/passwd", filepath.Join(landing, "requirements.txt.new")); err != nil {
		t.Fatal(err)
	}

	if err := DiffCheck(context.Background(), landing, []string{"requirements.txt.new"}); err == nil {
		t.Fatal("expected DiffCheck to reject a symlink even if the name is allowlisted")
	}
}

func TestSyncTreeRejectsSymlink(t *testing.T) {
	sandbox := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(sandbox, "evil")); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := SyncTree(sandbox, dst); err == nil {
		t.Fatal("expected SyncTree to reject a symlink in the source tree")
	}
}

func TestSyncTreeRejectsSandboxDeletion(t *testing.T) {
	sandbox := t.TempDir()
	dst := t.TempDir()
	writeFile(t, dst, "tracked.txt", "base\n")

	if err := SyncTree(sandbox, dst); err == nil || !strings.Contains(err.Error(), "deleted tracked file") {
		t.Fatalf("expected sandbox deletion to be rejected, got %v", err)
	}
}

func TestCommitAndPushReviewBranch(t *testing.T) {
	work := newRepoWithRemote(t)
	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}
	landing, cleanup, err := NewLandingCopy(context.Background(), work, baseSHA)
	if err != nil {
		t.Fatalf("NewLandingCopy: %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	run(t, landing, "config", "user.email", "test@example.com")
	run(t, landing, "config", "user.name", "test")

	writeFile(t, landing, "requirements.txt", "flask==2.0.1\n")
	if err := DiffCheck(context.Background(), landing, []string{"requirements.txt"}); err != nil {
		t.Fatalf("DiffCheck: %v", err)
	}

	summary := CommitSummary{Date: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC), Packages: []string{"flask 2.0.0 -> 2.0.1"}}
	if err := Commit(context.Background(), landing, []string{"requirements.txt"}, summary); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	ws := config.Workspace{Remote: "origin", Branch: "main"}
	git := config.GitConfig{PushMode: "review_branch"}
	branch, err := Push(context.Background(), landing, ws, git, "myproject", time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if branch != "vuelta/deps/myproject-2026-07-13" {
		t.Fatalf("unexpected branch name %q", branch)
	}

	// Verify the branch actually landed on the remote.
	out := run(t, work, "ls-remote", "origin", "refs/heads/"+branch)
	if strings.TrimSpace(out) == "" {
		t.Fatalf("expected branch %s to exist on remote", branch)
	}
}

func TestChangedPathsPreservesQuotedAndNewlinePath(t *testing.T) {
	work := newRepoWithRemote(t)
	name := "deps/\n\"quoted\".lock"
	writeFile(t, work, name, "lock\n")

	if err := DiffCheck(context.Background(), work, []string{name}); err != nil {
		t.Fatalf("DiffCheck: %v", err)
	}
	paths, err := ChangedPaths(context.Background(), work)
	if err != nil {
		t.Fatalf("ChangedPaths: %v", err)
	}
	if len(paths) != 1 || paths[0] != name {
		t.Fatalf("ChangedPaths = %q, want exact path %q", paths, name)
	}
	if err := Commit(context.Background(), work, []string{name}, CommitSummary{Date: time.Now()}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	committed := run(t, work, "diff-tree", "--name-only", "-z", "--no-commit-id", "-r", "HEAD^", "HEAD")
	if committed != name+"\x00" {
		t.Fatalf("committed paths = %q, want exact path %q", committed, name)
	}
}

func TestCommitRechecksPostDiffMutation(t *testing.T) {
	work := newRepoWithRemote(t)
	writeFile(t, work, "requirements.txt", "flask==2.0.1\n")
	if err := DiffCheck(context.Background(), work, []string{"requirements.txt"}); err != nil {
		t.Fatalf("DiffCheck: %v", err)
	}
	writeFile(t, work, "nested/requirements.txt", "malicious\n")
	headBefore := strings.TrimSpace(run(t, work, "rev-parse", "HEAD"))

	err := Commit(context.Background(), work, []string{"requirements.txt"}, CommitSummary{Date: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "outside git.allowed_changed_paths") {
		t.Fatalf("Commit error = %v, want final allowlist rejection", err)
	}
	headAfter := strings.TrimSpace(run(t, work, "rev-parse", "HEAD"))
	if headAfter != headBefore {
		t.Fatalf("HEAD changed after rejected final policy check: %s -> %s", headBefore, headAfter)
	}
}

func TestCommitRejectsUnsupportedStagedChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
		allow  []string
	}{
		{
			name: "delete",
			mutate: func(t *testing.T, work string) {
				if err := os.Remove(filepath.Join(work, "requirements.txt")); err != nil {
					t.Fatal(err)
				}
			},
			allow: []string{"requirements.txt"},
		},
		{
			name: "rename",
			mutate: func(t *testing.T, work string) {
				if err := os.Rename(filepath.Join(work, "requirements.txt"), filepath.Join(work, "requirements.lock")); err != nil {
					t.Fatal(err)
				}
			},
			allow: []string{"requirements.txt", "requirements.lock"},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, work string) {
				if err := os.Remove(filepath.Join(work, "requirements.txt")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("README.md", filepath.Join(work, "requirements.txt")); err != nil {
					t.Fatal(err)
				}
			},
			allow: []string{"requirements.txt"},
		},
		{
			name: "mode",
			mutate: func(t *testing.T, work string) {
				if err := os.Chmod(filepath.Join(work, "requirements.txt"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			allow: []string{"requirements.txt"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			work := newRepoWithRemote(t)
			tt.mutate(t, work)
			headBefore := strings.TrimSpace(run(t, work, "rev-parse", "HEAD"))
			if err := Commit(context.Background(), work, tt.allow, CommitSummary{Date: time.Now()}); err == nil {
				t.Fatalf("Commit accepted %s change", tt.name)
			}
			headAfter := strings.TrimSpace(run(t, work, "rev-parse", "HEAD"))
			if headAfter != headBefore {
				t.Fatalf("HEAD changed after rejected %s", tt.name)
			}
		})
	}
}

func TestPushDirectBranchRequiresFastForward(t *testing.T) {
	work := newRepoWithRemote(t)

	// Diverge the remote after fetching, so HEAD is no longer a descendant.
	remoteURL := strings.TrimSpace(run(t, work, "remote", "get-url", "origin"))
	other := t.TempDir()
	run(t, other, "clone", "-q", remoteURL, ".")
	run(t, other, "config", "user.email", "test@example.com")
	run(t, other, "config", "user.name", "test")
	writeFile(t, other, "requirements.txt", "flask==9.9.9\n")
	run(t, other, "add", "-A")
	run(t, other, "commit", "-q", "-m", "someone else's change")
	run(t, other, "push", "-q", "origin", "main")

	baseSHA, err := FetchAndBaseSHA(context.Background(), work, "origin", "main")
	if err != nil {
		t.Fatalf("FetchAndBaseSHA: %v", err)
	}
	_ = baseSHA

	run(t, work, "config", "user.email", "test@example.com")
	run(t, work, "config", "user.name", "test")
	writeFile(t, work, "requirements.txt", "flask==2.0.1\n")
	run(t, work, "add", "-A")
	run(t, work, "commit", "-q", "-m", "my change")

	ws := config.Workspace{Remote: "origin", Branch: "main"}
	git := config.GitConfig{PushMode: "direct_branch"}
	if _, err := Push(context.Background(), work, ws, git, "myproject", time.Now()); err == nil {
		t.Fatal("expected direct_branch push to be blocked when not a fast-forward")
	}
}

func TestCommitSummaryMessage(t *testing.T) {
	s := CommitSummary{
		Date:     time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
		Packages: []string{"flask 2.0.0 -> 2.0.1"},
		CVERefs:  []string{"CVE-2026-0001"},
	}
	msg := s.Message()
	if !strings.HasPrefix(msg, "chore(deps): update dependencies 2026-07-13") {
		t.Fatalf("unexpected message prefix: %q", msg)
	}
	if !strings.Contains(msg, "flask 2.0.0 -> 2.0.1") {
		t.Fatalf("expected package summary in message: %q", msg)
	}
	if !strings.Contains(msg, "CVE-2026-0001") {
		t.Fatalf("expected CVE ref in message: %q", msg)
	}
}
