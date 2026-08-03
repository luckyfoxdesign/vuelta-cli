package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

func writeVerifyFixtureProject(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"scripts":{"build":"tsc"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	projectConfig := &config.ProjectConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		Workspace: config.Workspace{
			Path: ".", Stack: config.StackNode, PackageManager: "npm",
			Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
			AllowedChangedPaths: []string{"package.json", "package-lock.json"},
		},
	}
	plan, err := configinit.PlanProjectConfigWrite(projectConfig, filepath.Join(project, projectConfigName))
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(filepath.Join(project, projectConfigName)); err != nil {
		t.Fatal(err)
	}
	return project
}

func writeVerifyMachineConfig(t *testing.T) string {
	t.Helper()
	cfg := configinit.NewConfig()
	cfg.Docker = &config.DockerConfig{Developer: &config.DockerEndpointConfig{
		Socket: "/approved/docker.sock",
		ExpectedDaemon: config.DockerDaemonIdentity{
			ID: "daemon-reviewed", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
			MinimumAPIVersion: "1.49", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
		},
	}}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := configinit.Write(cfg, path, false); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProjectVerifyInitWritesComposeFile(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	configPath := writeVerifyMachineConfig(t)
	if err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project}); err != nil {
		t.Fatalf("project verify init: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(project, "compose.verify.yml"))
	if err != nil {
		t.Fatalf("read generated compose.verify.yml: %v", err)
	}
	if !strings.Contains(string(data), "read_only: true") {
		t.Fatalf("generated compose is missing read_only: true:\n%s", data)
	}
}

func TestProjectVerifyInitUsesProjectPolicyWithDefaultMachineAuthority(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	if _, _, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, ""); err != nil {
		t.Fatalf("onboard project: %v", err)
	}
	machine := configinit.NewConfig()
	machine.Docker = &config.DockerConfig{Developer: &config.DockerEndpointConfig{
		Socket: "/approved/docker.sock",
		ExpectedDaemon: config.DockerDaemonIdentity{
			ID: "daemon-reviewed", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
			MinimumAPIVersion: "1.49", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
		},
	}}
	machine.Workspaces = []config.Workspace{{
		Name: "stale-machine-entry", Path: project, Stack: config.StackNode, PackageManager: "npm",
		Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
		AllowedChangedPaths: []string{"package.json", "package-lock.json"},
	}}
	machinePath, err := defaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := configinit.Write(machine, machinePath, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(machinePath)
	if err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"project", "verify", "init", "--directory", project}); err != nil {
		t.Fatalf("project verify init: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(project, "compose.verify.yml")); err != nil {
		t.Fatalf("read generated compose.verify.yml: %v", err)
	}
	after, err := os.ReadFile(machinePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("project verify init rewrote the machine config")
	}
}

func TestProjectVerifyInitRequiresPolicyInSelectedProject(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"scripts":{"build":"tsc"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeVerifyMachineConfig(t)
	err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project})
	if err == nil || !strings.Contains(err.Error(), "run vuelta scan --directory") {
		t.Fatalf("missing project policy error = %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(project, "compose.verify.yml")); !os.IsNotExist(statErr) {
		t.Fatalf("missing project policy created compose.verify.yml: %v", statErr)
	}
}

func TestProjectVerifyInitNeverOverwrites(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	configPath := writeVerifyMachineConfig(t)
	existing := filepath.Join(project, "compose.verify.yml")
	if err := os.WriteFile(existing, []byte("hand-written"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already-exists error, got %v", err)
	}
	data, readErr := os.ReadFile(existing)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "hand-written" {
		t.Fatal("existing compose.verify.yml must be left untouched")
	}
}

func TestProjectVerifyInitDigestFailureLeavesNoFile(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "", errors.New("registry unreachable")
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	configPath := writeVerifyMachineConfig(t)
	err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project})
	if err == nil || !strings.Contains(err.Error(), "registry unreachable") {
		t.Fatalf("expected digest resolution error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(project, "compose.verify.yml")); !os.IsNotExist(statErr) {
		t.Fatal("compose.verify.yml must not exist after digest resolution failure")
	}
}

func TestProjectVerifyInitRefreshImageUpdatesExistingPin(t *testing.T) {
	previous := resolveVerifyDigest
	t.Cleanup(func() { resolveVerifyDigest = previous })
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	project := writeVerifyFixtureProject(t)
	configPath := writeVerifyMachineConfig(t)
	if err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project}); err != nil {
		t.Fatal(err)
	}
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "sha256:" + strings.Repeat("2", 64), nil
	}
	if err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project, "--refresh-image"}); err != nil {
		t.Fatalf("refresh image: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(project, "compose.verify.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sha256:"+strings.Repeat("1", 64)) || !strings.Contains(string(data), "sha256:"+strings.Repeat("2", 64)) {
		t.Fatalf("refreshed compose has the wrong digest:\n%s", data)
	}
}

func TestProjectVerifyInitRefreshImageRejectsScript(t *testing.T) {
	err := run([]string{"project", "verify", "init", "--refresh-image", "--script", "build"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("refresh/script error = %v", err)
	}
}

func onboardVerifyProject(t *testing.T) (string, string) {
	t.Helper()
	project := writeVerifyFixtureProject(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	cfg, selection, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, "")
	if err != nil {
		t.Fatalf("onboard project: %v", err)
	}
	if len(cfg.Workspaces) != 1 || cfg.Workspaces[0].Verification.State != config.VerificationScanOnly {
		t.Fatalf("onboarded verification = %#v", cfg.Workspaces)
	}
	return project, selection.Path
}

func writeGeneratedVerifyCompose(t *testing.T, project string) {
	t.Helper()
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })
	configPath := writeVerifyMachineConfig(t)
	if err := run([]string{"--config", configPath, "project", "verify", "init", "--directory", project}); err != nil {
		t.Fatalf("project verify init: %v", err)
	}
}

func TestProjectVerifyApprovePromotesExistingComposeAndPrintsExactPlan(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	writeGeneratedVerifyCompose(t, project)
	composePath := filepath.Join(project, "compose.verify.yml")
	generated, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	handWritten := append([]byte("# retained hand-written compose\n"), generated...)
	if err := os.WriteFile(composePath, handWritten, 0o644); err != nil {
		t.Fatal(err)
	}

	var runErr error
	_, stderr := captureScanOutput(t, func() {
		runErr = run([]string{"project", "verify", "approve", "--directory", project, "--yes"})
	})
	if runErr != nil {
		t.Fatalf("project verify approve: %v", runErr)
	}
	for _, wanted := range []string{"verification plan: build-compose-verify:", `argv=["npm" "run" "build"]`, "state: ready", projectPath} {
		if !strings.Contains(stderr, wanted) {
			t.Fatalf("approval output is missing %q:\n%s", wanted, stderr)
		}
	}
	promoted, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Workspace.Verification.State != config.VerificationReady || len(promoted.Workspace.Verification.Steps) != 1 {
		t.Fatalf("promoted verification = %#v", promoted.Workspace.Verification)
	}
	if !strings.HasPrefix(promoted.Workspace.Verification.Steps[0].ScriptBodyHash, "sha256:") {
		t.Fatalf("script body was not pinned: %#v", promoted.Workspace.Verification.Steps[0])
	}
	afterCompose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterCompose) != string(handWritten) {
		t.Fatal("approval rewrote the existing Compose file")
	}
}

func TestProjectVerifyApproveRequiresConfirmationAndWritesNothing(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	writeGeneratedVerifyCompose(t, project)
	before, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	err = run([]string{"--no-input", "project", "verify", "approve", "--directory", project})
	if err == nil || !strings.Contains(err.Error(), "requires confirmation") {
		t.Fatalf("non-interactive approval error = %v", err)
	}
	after, readErr := os.ReadFile(projectPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("unconfirmed approval modified .vuelta.yaml")
	}
}

func TestProjectVerifyApproveWithoutServicePointsToInit(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	before, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	err = run([]string{"project", "verify", "approve", "--directory", project, "--yes"})
	if err == nil || !strings.Contains(err.Error(), "project verify init") {
		t.Fatalf("missing-service approval error = %v", err)
	}
	after, readErr := os.ReadFile(projectPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("missing-service rejection modified .vuelta.yaml")
	}
}

func TestProjectVerifyApproveRejectsInvalidProfileBeforeWrite(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	invalidCompose := "services:\n  verify:\n    command: [npm, run, build]\n"
	if err := os.WriteFile(filepath.Join(project, "compose.verify.yml"), []byte(invalidCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	err = run([]string{"project", "verify", "approve", "--directory", project, "--yes"})
	if err == nil || !strings.Contains(err.Error(), "Compose policy") {
		t.Fatalf("invalid-profile approval error = %v", err)
	}
	after, readErr := os.ReadFile(projectPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("invalid-profile rejection modified .vuelta.yaml")
	}
}

func TestProjectVerifyApproveRefreshesReadyProfileAfterSafeScriptDrift(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	writeGeneratedVerifyCompose(t, project)
	if err := run([]string{"project", "verify", "approve", "--directory", project, "--yes"}); err != nil {
		t.Fatal(err)
	}
	approved, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := approved.Workspace.Verification.Steps[0].ScriptBodyHash
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"scripts":{"build":"tsc --pretty false"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadProject(projectPath); err == nil || !strings.Contains(err.Error(), "re-approve") {
		t.Fatalf("ordinary load accepted drift: %v", err)
	}
	if err := run([]string{"project", "verify", "approve", "--directory", project, "--yes"}); err != nil {
		t.Fatalf("re-approval failed: %v", err)
	}
	refreshed, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Workspace.Verification.Steps[0].ScriptBodyHash == firstHash {
		t.Fatal("re-approval did not refresh the script body hash")
	}
}

func TestBuildReadyVerificationUsesExistingSelectionRules(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	writeGeneratedVerifyCompose(t, project)
	loaded, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := loaded.ResolvedWorkspace(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := configinit.Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := discovery.BuildReadyVerification(workspace, []string{"build-compose-verify"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.State != config.VerificationReady || len(profile.Steps) != 1 || profile.Steps[0].Name != "build-compose-verify" {
		t.Fatalf("selected profile = %#v", profile)
	}
}
