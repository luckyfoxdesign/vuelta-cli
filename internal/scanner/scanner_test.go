package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	run(t, dir, "config", "user.email", "test@example.com")
	run(t, dir, "config", "user.name", "test")
	return dir
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightCleanPythonPoetry(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "pyproject.toml", "[project]\n")
	writeFile(t, dir, "poetry.lock", "")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "init")

	ws := config.Workspace{Path: dir, Stack: config.StackPython, PackageManager: "poetry"}
	res, err := Preflight(context.Background(), ws)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.Skip != SkipNone {
		t.Fatalf("expected no skip, got %q", res.Skip)
	}
}

func TestPreflightDirtySkipped(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "pyproject.toml", "[project]\n")
	writeFile(t, dir, "poetry.lock", "")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "init")
	writeFile(t, dir, "poetry.lock", "changed")

	ws := config.Workspace{Path: dir, Stack: config.StackPython, PackageManager: "poetry"}
	res, err := Preflight(context.Background(), ws)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.Skip != SkipDirty {
		t.Fatalf("expected SkipDirty, got %q", res.Skip)
	}
}

func TestPreflightMissingStackFiles(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "README.md", "hello")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "init")

	ws := config.Workspace{Path: dir, Stack: config.StackPython, PackageManager: "poetry"}
	res, err := Preflight(context.Background(), ws)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.Skip != SkipStackFiles {
		t.Fatalf("expected SkipStackFiles, got %q", res.Skip)
	}
}

func TestPreflightUnknownRemote(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "pyproject.toml", "[project]\n")
	writeFile(t, dir, "poetry.lock", "")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "init")

	ws := config.Workspace{Path: dir, Stack: config.StackPython, PackageManager: "poetry", Remote: "origin"}
	res, err := Preflight(context.Background(), ws)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.Skip != SkipRemote {
		t.Fatalf("expected SkipRemote, got %q", res.Skip)
	}
}

func TestPreflightDockerStackSkipsManifestCheck(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "Dockerfile", "FROM scratch\n")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "init")

	ws := config.Workspace{Path: dir, Stack: config.StackDocker}
	res, err := Preflight(context.Background(), ws)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.Skip != SkipNone {
		t.Fatalf("expected no skip, got %q", res.Skip)
	}
}

func TestCheckToolsPresent(t *testing.T) {
	if err := checkTools([]string{"git"}); err != nil {
		t.Fatalf("checkTools: %v (git is installed in the test image)", err)
	}
}

func TestCheckToolsMissing(t *testing.T) {
	if err := checkTools([]string{"git", "definitely-not-a-real-binary-xyz"}); err == nil {
		t.Fatal("expected error for a tool missing from PATH")
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

func TestSnapshotIdentityBindsExactStageManifestAndReviewedConfig(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, "package.json", `{}`)
	writeFile(t, dir, "package-lock.json", `{"lockfileVersion":3}`)
	writeFile(t, dir, ".npmrc", "registry=https://registry.npmjs.org/\n")
	if err := os.Mkdir(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "src/main.js", "unrelated")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "init")
	workspace := config.Workspace{Path: dir, Stack: config.StackNode, PackageManager: "npm"}

	withoutConfig, err := IdentityForSnapshotWithOptions(context.Background(), workspace, IdentityOptions{
		Stages: []scaninput.Stage{scaninput.StagePackageCandidates},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withoutConfig.InputHashes[".npmrc"]; ok {
		t.Fatal("manager config entered snapshot identity without explicit opt-in")
	}
	if _, ok := withoutConfig.InputHashes["src/main.js"]; ok {
		t.Fatal("unrelated source entered snapshot identity")
	}

	withConfig, err := IdentityForSnapshotWithOptions(context.Background(), workspace, IdentityOptions{
		Stages: []scaninput.Stage{scaninput.StagePackageCandidates}, AllowProjectConfig: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withConfig.InputHashes[".npmrc"]; !ok || withConfig.InputManifestHash == withoutConfig.InputManifestHash {
		t.Fatal("reviewed manager config is not separately bound to input identity")
	}
}
