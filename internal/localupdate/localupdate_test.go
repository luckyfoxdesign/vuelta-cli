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

func TestScanUsesPrivateMinimalEnvironmentAndCleansItUp(t *testing.T) {
	t.Setenv("PATH", "/hostile/bin")
	t.Setenv("HTTPS_PROXY", "http://hostile.invalid")
	t.Setenv("NPM_CONFIG_USERCONFIG", "/hostile/npmrc")
	t.Setenv("GITHUB_TOKEN", "must-not-leak")
	root := npmProject(t)
	var privateRoot string
	s := testService(t, func(_ context.Context, binary, dir string, _ []string, env []string) (CommandResult, error) {
		if !filepath.IsAbs(binary) || dir != root {
			t.Fatalf("runner binary=%q dir=%q", binary, dir)
		}
		values := make(map[string]string, len(env))
		for _, item := range env {
			name, value, ok := strings.Cut(item, "=")
			if !ok {
				t.Fatalf("invalid environment entry %q", item)
			}
			values[name] = value
		}
		for _, forbidden := range []string{"HTTPS_PROXY", "NPM_CONFIG_USERCONFIG", "GITHUB_TOKEN"} {
			if _, ok := values[forbidden]; ok {
				t.Fatalf("hostile variable %s was inherited", forbidden)
			}
		}
		if values["PATH"] == "/hostile/bin" {
			t.Fatal("caller PATH was inherited")
		}
		privateRoot = filepath.Dir(values["HOME"])
		for _, path := range []string{privateRoot, values["HOME"], values["XDG_CACHE_HOME"], values["XDG_CONFIG_HOME"], values["TMPDIR"]} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("private path %q info=%v error=%v", path, info, err)
			}
		}
		return CommandResult{Output: "{}"}, nil
	})
	if _, err := s.Scan(context.Background(), root, config.LocalPackagePolicy{}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(privateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private invocation root still exists: %v", err)
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

func TestUpdateAppliesOnlyDependencyFilesFromPrivateCopy(t *testing.T) {
	root := npmProject(t)
	writeLocalFile(t, root, "README.md", "host")
	calls := 0
	s := testService(t, func(_ context.Context, _ string, dir string, _ []string, _ []string) (CommandResult, error) {
		calls++
		if calls == 1 {
			return CommandResult{Output: `{"example":{"current":"1.0.0","latest":"2.0.0"}}`, ExitCode: 1}, nil
		}
		if calls == 3 {
			writeLocalFile(t, dir, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
			writeLocalFile(t, dir, "package-lock.json", `changed`)
		}
		return CommandResult{}, nil
	})
	_, err := s.Update(context.Background(), root, config.LocalPackagePolicy{AllowedPackages: []string{"example"}}, []Candidate{{Name: "example", Target: "2.0.0"}}, UpdateOptions{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile(filepath.Join(root, "package.json"))
	readme, _ := os.ReadFile(filepath.Join(root, "README.md"))
	if !strings.Contains(string(manifest), "2.0.0") || string(readme) != "host" {
		t.Fatalf("host result manifest=%q README=%q", manifest, readme)
	}
}

func TestUpdateDryRunExecutesInPrivateCopyWithoutHostWrites(t *testing.T) {
	root := npmProject(t)
	before, _ := os.ReadFile(filepath.Join(root, "package.json"))
	calls := 0
	s := testService(t, func(_ context.Context, _ string, dir string, _ []string, _ []string) (CommandResult, error) {
		calls++
		if calls == 1 {
			return CommandResult{Output: `{"example":{"current":"1.0.0","latest":"2.0.0"}}`, ExitCode: 1}, nil
		}
		if calls == 3 {
			writeLocalFile(t, dir, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
			writeLocalFile(t, dir, "package-lock.json", `changed`)
		}
		return CommandResult{}, nil
	})
	_, err := s.Update(context.Background(), root, config.LocalPackagePolicy{AllowedPackages: []string{"example"}}, []Candidate{{Name: "example", Target: "2.0.0"}}, UpdateOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if string(after) != string(before) || calls != 3 {
		t.Fatalf("dry-run host manifest=%q calls=%d", after, calls)
	}
}

func TestPrivateCopyRejectsApprovedConfigMutationWithoutTouchingHost(t *testing.T) {
	root := t.TempDir()
	writeLocalFile(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
	writeLocalFile(t, root, "bun.lock", "lock")
	writeLocalFile(t, root, "bunfig.toml", "telemetry = false")
	calls := 0
	s := testService(t, func(_ context.Context, _ string, dir string, _ []string, _ []string) (CommandResult, error) {
		calls++
		if calls == 1 {
			return CommandResult{Output: `{"example":{"current":"1.0.0","latest":"2.0.0"}}`, ExitCode: 1}, nil
		}
		if calls == 3 {
			writeLocalFile(t, dir, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
			writeLocalFile(t, dir, "bun.lock", `changed`)
			writeLocalFile(t, dir, "bunfig.toml", "telemetry = true!")
		}
		return CommandResult{}, nil
	})
	_, err := s.Update(context.Background(), root, config.LocalPackagePolicy{AllowedPackages: []string{"example"}}, []Candidate{{Name: "example", Target: "2.0.0"}}, UpdateOptions{Apply: true, AllowProjectConfig: true})
	if err == nil || !strings.Contains(err.Error(), "unallowlisted") {
		t.Fatalf("Update error = %v, want config mutation rejection", err)
	}
	configData, _ := os.ReadFile(filepath.Join(root, "bunfig.toml"))
	if string(configData) != "telemetry = false" {
		t.Fatalf("host package-manager config changed: %q", configData)
	}
}

func TestPrivateCopyRefusesToOverwriteConcurrentHostInputChange(t *testing.T) {
	root := npmProject(t)
	changed, err := InPrivateCopy(root, false, true, func(project Project) error {
		writeLocalFile(t, project.Root, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
		writeLocalFile(t, root, "package.json", `{"dependencies":{"external":"3.0.0"}}`)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed during private update") {
		t.Fatalf("InPrivateCopy changed=%v error=%v", changed, err)
	}
	host, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if !strings.Contains(string(host), "external") {
		t.Fatalf("concurrent host change was overwritten: %q", host)
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
	if string(readme) != "before" {
		t.Fatalf("host unallowlisted file = %q, want untouched private-copy isolation", readme)
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
