package localupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func writeLocalFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func npmProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeLocalFile(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
	writeLocalFile(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	return root
}

func testService(t *testing.T, run Runner) Service {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Service{
		Run:      run,
		LookPath: func(string) (string, error) { return binary, nil },
		LockPath: func(string) (string, error) { return filepath.Join(t.TempDir(), "local.lock"), nil },
	}
}

func TestDetectRejectsManifestSymlink(t *testing.T) {
	root := t.TempDir()
	writeLocalFile(t, root, "package-lock.json", "{}")
	if err := os.Symlink("package-lock.json", filepath.Join(root, "package.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(root); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("Detect error = %v, want rejected symlink", err)
	}
}

func TestScanRejectsManagerInsideProject(t *testing.T) {
	root := npmProject(t)
	manager := filepath.Join(root, "npm")
	writeLocalFile(t, root, "npm", "not executable")
	s := Service{LookPath: func(string) (string, error) { return manager, nil }}
	_, err := s.Scan(context.Background(), root, config.LocalPackagePolicy{}, false)
	if err == nil || !strings.Contains(err.Error(), "inside the target") {
		t.Fatalf("Scan error = %v, want target binary rejection", err)
	}
}

func TestPipToolsScanRequiresSystemPipCompileAndPip(t *testing.T) {
	root := t.TempDir()
	writeLocalFile(t, root, "requirements.in", "example==1.0.0\n")
	writeLocalFile(t, root, "requirements.txt", "example==1.0.0\n")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var lookedUp []string
	s := Service{
		Run: func(context.Context, string, string, []string, []string) (CommandResult, error) {
			return CommandResult{Output: "[]"}, nil
		},
		LookPath: func(name string) (string, error) {
			lookedUp = append(lookedUp, name)
			return binary, nil
		},
	}
	if _, err := s.Scan(context.Background(), root, config.LocalPackagePolicy{}, false); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got, want := strings.Join(lookedUp, ","), "pip-compile,pip"; got != want {
		t.Fatalf("LookPath calls = %q, want %q", got, want)
	}
}

func TestScanRejectsProjectManagerConfigWithoutOptIn(t *testing.T) {
	root := npmProject(t)
	writeLocalFile(t, root, ".npmrc", "registry=https://example.invalid")
	s := testService(t, func(context.Context, string, string, []string, []string) (CommandResult, error) {
		return CommandResult{}, nil
	})
	_, err := s.Scan(context.Background(), root, config.LocalPackagePolicy{}, false)
	if err == nil || !strings.Contains(err.Error(), "allow-project-config") {
		t.Fatalf("Scan error = %v, want configuration rejection", err)
	}
}

func TestUpdateRequiresExplicitApply(t *testing.T) {
	root := npmProject(t)
	s := testService(t, nil)
	_, err := s.Update(context.Background(), root, config.LocalPackagePolicy{AllowedPackages: []string{"example"}}, []Candidate{{Name: "example", Target: "2.0.0"}}, UpdateOptions{})
	if err == nil || !strings.Contains(err.Error(), "requires --apply") {
		t.Fatalf("Update error = %v, want explicit apply error", err)
	}
}

func TestUpdateRestoresDependencyFilesWhenManagerFails(t *testing.T) {
	root := npmProject(t)
	beforeManifest, _ := os.ReadFile(filepath.Join(root, "package.json"))
	beforeLock, _ := os.ReadFile(filepath.Join(root, "package-lock.json"))
	calls := 0
	s := testService(t, func(_ context.Context, _ string, dir string, _ []string, _ []string) (CommandResult, error) {
		calls++
		switch calls {
		case 1:
			return CommandResult{Output: `{"example":{"current":"1.0.0","latest":"2.0.0"}}`, ExitCode: 1}, nil
		case 2:
			return CommandResult{}, nil
		case 3:
			writeLocalFile(t, dir, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
			writeLocalFile(t, dir, "package-lock.json", `changed`)
			return CommandResult{Output: "failed", ExitCode: 1}, nil
		default:
			return CommandResult{}, errors.New("unexpected invocation")
		}
	})
	_, err := s.Update(context.Background(), root, config.LocalPackagePolicy{AllowedPackages: []string{"example"}}, []Candidate{{Name: "example", Target: "2.0.0"}}, UpdateOptions{Apply: true})
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("Update error = %v, want manager failure", err)
	}
	afterManifest, _ := os.ReadFile(filepath.Join(root, "package.json"))
	afterLock, _ := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if string(afterManifest) != string(beforeManifest) || string(afterLock) != string(beforeLock) {
		t.Fatalf("dependency files were not restored: manifest=%q lock=%q", afterManifest, afterLock)
	}
}

func TestUpdateDetectsUnallowlistedChangeAndRestoresDependencies(t *testing.T) {
	root := npmProject(t)
	writeLocalFile(t, root, "README.md", "before")
	beforeManifest, _ := os.ReadFile(filepath.Join(root, "package.json"))
	calls := 0
	s := testService(t, func(_ context.Context, _ string, dir string, _ []string, _ []string) (CommandResult, error) {
		calls++
		if calls == 1 {
			return CommandResult{Output: `{"example":{"current":"1.0.0","latest":"2.0.0"}}`, ExitCode: 1}, nil
		}
		if calls == 3 {
			writeLocalFile(t, dir, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
			writeLocalFile(t, dir, "package-lock.json", `changed`)
			writeLocalFile(t, dir, "README.md", "changed")
		}
		return CommandResult{}, nil
	})
	_, err := s.Update(context.Background(), root, config.LocalPackagePolicy{AllowedPackages: []string{"example"}}, []Candidate{{Name: "example", Target: "2.0.0"}}, UpdateOptions{Apply: true})
	if err == nil || !strings.Contains(err.Error(), "unallowlisted") {
		t.Fatalf("Update error = %v, want allowlist violation", err)
	}
	afterManifest, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if string(afterManifest) != string(beforeManifest) {
		t.Fatalf("manifest was not restored: %q", afterManifest)
	}
	readme, _ := os.ReadFile(filepath.Join(root, "README.md"))
	if string(readme) != "changed" {
		t.Fatalf("unallowlisted change = %q, want preserved for review", readme)
	}
}

func TestValidateSelectionRejectsFlagInjection(t *testing.T) {
	policy := config.LocalPackagePolicy{AllowedPackages: []string{"example"}}
	available := []Candidate{{Name: "example", Target: "2.0.0"}}
	err := validateSelection(policy, available, []Candidate{{Name: "--registry", Target: "https://evil.invalid"}})
	if err == nil || !strings.Contains(err.Error(), "invalid package") {
		t.Fatalf("validateSelection error = %v, want flag rejection", err)
	}
}

func TestSafeTextRemovesTerminalControls(t *testing.T) {
	if got := safeText("ok\x1b[31m"); got != "ok[31m" {
		t.Fatalf("safeText = %q", got)
	}
}
