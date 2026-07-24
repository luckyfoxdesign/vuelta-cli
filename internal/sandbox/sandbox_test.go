package sandbox

import (
	"archive/tar"
	"bytes"
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

func TestSafeArchivePathRejectsProjectLocalVueltaState(t *testing.T) {
	for _, name := range []string{".vuelta", ".vuelta/last-scan.md", ".vuelta/snapshots/id.json"} {
		if _, err := safeArchivePath(name, defaultArchiveLimits); err == nil {
			t.Fatalf("safeArchivePath accepted private state %q", name)
		}
	}
}

func TestPrepareRejectsTrackedSymlinkArchiveMember(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture requires a POSIX filesystem")
	}
	repoPath, _ := repo(t)
	// A *tracked* symlink is the adversarial case the untracked-symlink test does
	// not cover: git archive emits it as a symlink tar member, so extraction must
	// refuse it rather than materialize a link that escapes the working copy.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("host secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(repoPath, "escape")); err != nil {
		t.Fatal(err)
	}
	git(t, repoPath, "add", "escape")
	git(t, repoPath, "commit", "-q", "-m", "add tracked symlink")
	sha := strings.TrimSpace(git(t, repoPath, "rev-parse", "HEAD"))

	dir, cleanup, err := Prepare(context.Background(), repoPath, sha)
	if err == nil {
		_ = cleanup()
		t.Fatalf("Prepare accepted a tracked symlink archive member; sandbox at %s", dir)
	}
	if !strings.Contains(err.Error(), "not a regular file or directory") {
		t.Fatalf("Prepare error = %v, want tracked-symlink rejection", err)
	}
	if dir != "" {
		t.Fatalf("Prepare returned a sandbox path %q on failure", dir)
	}
}

// addFile writes one regular-file member. The declared size may deliberately
// disagree with the body: extract must fail closed on the metadata alone.
func addFile(t *testing.T, tw *tar.Writer, name string, size int64, body []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: size}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
}

func TestExtractEnforcesArchiveLimits(t *testing.T) {
	lim := archiveLimits{
		maxFileBytes:  8,
		maxTotalBytes: 12,
		maxEntries:    4,
		maxPathDepth:  3,
		maxPathBytes:  32,
	}
	cases := []struct {
		name    string
		build   func(t *testing.T, tw *tar.Writer)
		wantErr string
	}{
		{
			name: "per-file size limit",
			build: func(t *testing.T, tw *tar.Writer) {
				addFile(t, tw, "big.bin", lim.maxFileBytes+1, nil)
			},
			wantErr: "per-file limit",
		},
		{
			name: "total size limit",
			build: func(t *testing.T, tw *tar.Writer) {
				addFile(t, tw, "a.bin", 8, bytes.Repeat([]byte("x"), 8))
				addFile(t, tw, "b.bin", 8, nil)
			},
			wantErr: "total bytes",
		},
		{
			name: "entry count limit",
			build: func(t *testing.T, tw *tar.Writer) {
				for _, name := range []string{"a", "b", "c", "d", "e"} {
					addFile(t, tw, name, 0, nil)
				}
			},
			wantErr: "entries",
		},
		{
			name: "path depth limit",
			build: func(t *testing.T, tw *tar.Writer) {
				addFile(t, tw, "a/b/c/d", 0, nil)
			},
			wantErr: "depth",
		},
		{
			name: "path length limit",
			build: func(t *testing.T, tw *tar.Writer) {
				addFile(t, tw, strings.Repeat("a", lim.maxPathBytes+1), 0, nil)
			},
			wantErr: "path length",
		},
		{
			name: "declared size exceeds actual data",
			build: func(t *testing.T, tw *tar.Writer) {
				addFile(t, tw, "short.bin", 8, []byte("abc"))
			},
			wantErr: "extract archive file short.bin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			// The stream is left unterminated on purpose: every case must
			// fail before extract needs a well-formed end-of-archive marker.
			tc.build(t, tar.NewWriter(&buf))
			err := extract(&buf, t.TempDir(), lim)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("extract error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestPrepareRejectsDeepPathAndLeavesNoSandbox(t *testing.T) {
	repoPath, _ := repo(t)
	deep := filepath.Join(strings.Split(strings.TrimSuffix(strings.Repeat("d/", 33), "/"), "/")...)
	if err := os.MkdirAll(filepath.Join(repoPath, deep), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, deep, "f.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repoPath, "add", ".")
	git(t, repoPath, "commit", "-q", "-m", "deep path")
	sha := strings.TrimSpace(git(t, repoPath, "rev-parse", "HEAD"))

	// Redirect sandbox creation so leftovers are detectable in isolation.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	dir, cleanup, err := Prepare(context.Background(), repoPath, sha)
	if err == nil {
		_ = cleanup()
		t.Fatalf("Prepare accepted an over-deep archive path; sandbox at %s", dir)
	}
	if !strings.Contains(err.Error(), "depth") {
		t.Fatalf("Prepare error = %v, want depth rejection", err)
	}
	if dir != "" {
		t.Fatalf("Prepare returned a sandbox path %q on failure", dir)
	}
	leftovers, globErr := filepath.Glob(filepath.Join(tmp, "vuelta-sandbox-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(leftovers) != 0 {
		t.Fatalf("partial sandbox left behind: %v", leftovers)
	}
}

func TestPrepareCleanupRemovesSandbox(t *testing.T) {
	repoPath, sha := repo(t)
	dir, cleanup, err := Prepare(context.Background(), repoPath, sha)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("sandbox still exists after cleanup: %v", err)
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
