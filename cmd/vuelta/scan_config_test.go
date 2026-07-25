package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

func TestSelectScanConfigurationCreatesAndReusesProjectConfig(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")

	cfg, selection, err := selectScanConfiguration(scanOptions{directory: project}, filepath.Join("unused", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if selection.Status != "created" || selection.Scope != "project" || !selection.OnboardingChanged || len(cfg.Workspaces) != 1 || cfg.Workspaces[0].Path != project {
		t.Fatalf("selection/config = %#v %#v", selection, cfg)
	}
	before, err := os.ReadFile(selection.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte("path: .")) || bytes.Contains(before, []byte("docker:")) || bytes.Contains(before, []byte("snapshot_state_dir")) {
		t.Fatalf("project config contains machine authority:\n%s", before)
	}
	ignore, err := os.ReadFile(filepath.Join(project, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ignore) != "/.vuelta/\n" {
		t.Fatalf("project .gitignore = %q", ignore)
	}

	_, reused, err := selectScanConfiguration(scanOptions{directory: project}, filepath.Join("unused", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(selection.Path)
	if err != nil {
		t.Fatal(err)
	}
	if reused.Status != "reused" || reused.OnboardingChanged || !bytes.Equal(before, after) {
		t.Fatal("second selection rewrote the project config")
	}
}

func TestSelectScanConfigurationDoesNotWriteOnAmbiguity(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")
	writeScanProjectFile(t, project, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")

	_, _, err := selectScanConfiguration(scanOptions{directory: project}, "")
	if err == nil || !strings.Contains(err.Error(), "--package-manager") {
		t.Fatalf("ambiguous detection error = %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(project, projectConfigName)); !os.IsNotExist(statErr) {
		t.Fatalf("ambiguous detection created config: %v", statErr)
	}
}

func TestSelectScanConfigurationExplicitConfigNeverCreatesLocalFile(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	global := filepath.Join(t.TempDir(), "config.yaml")
	if err := configinit.Write(configinit.NewConfig(), global, false); err != nil {
		t.Fatal(err)
	}
	_, selection, err := selectScanConfiguration(scanOptions{directory: project, explicitConfig: true}, global)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Scope != "machine" {
		t.Fatalf("selection = %#v", selection)
	}
	if _, statErr := os.Lstat(filepath.Join(project, projectConfigName)); !os.IsNotExist(statErr) {
		t.Fatalf("explicit config created local file: %v", statErr)
	}
}

func TestSelectScanConfigurationRecognizesExplicitProjectConfigBySchema(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")
	custom := filepath.Join(project, "project-policy.yaml")
	projectConfig := &config.ProjectConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		Workspace: config.Workspace{
			Name: "api", Path: ".", Stack: config.StackNode, PackageManager: "npm",
			Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
			AllowedChangedPaths: []string{"package.json", "package-lock.json"},
		},
	}
	plan, err := configinit.PlanProjectConfigWrite(projectConfig, custom)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(custom); err != nil {
		t.Fatal(err)
	}
	cfg, selection, err := selectScanConfiguration(scanOptions{explicitConfig: true}, custom)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Scope != "project" || cfg.Workspaces[0].Path != project {
		t.Fatalf("selection/config = %#v %#v", selection, cfg)
	}
}

func newAmbiguousDockerDiscovery(t *testing.T, root string) configinit.Discovery {
	t.Helper()
	digest := "alpine@sha256:" + strings.Repeat("a", 64)
	writeScanProjectFile(t, root, "Dockerfile", "FROM "+digest+"\n")
	return configinit.Discovery{
		Root: root, Stacks: []string{"docker", "python"},
		DockerFiles: []string{"Dockerfile"}, RuntimeImages: []string{digest},
	}
}

func TestResolveAmbiguousWorkspacePromptsWhenInteractive(t *testing.T) {
	root := t.TempDir()
	discovery := newAmbiguousDockerDiscovery(t, root)

	var askedFlag string
	var askedOptions []string
	chooseFlag := func(flag string, options []string) (string, error) {
		askedFlag, askedOptions = flag, options
		return "docker", nil
	}

	workspace, err := resolveAmbiguousWorkspace(discovery, configinit.Input{ScanOnly: true}, true, chooseFlag)
	if err != nil {
		t.Fatal(err)
	}
	if askedFlag != "--stack" || strings.Join(askedOptions, ",") != "docker,python" {
		t.Fatalf("chooseFlag called with %q %v", askedFlag, askedOptions)
	}
	if workspace.Stack != "docker" {
		t.Fatalf("workspace.Stack = %q, want docker", workspace.Stack)
	}
}

func TestResolveAmbiguousWorkspaceNonInteractiveFailsClosed(t *testing.T) {
	root := t.TempDir()
	discovery := newAmbiguousDockerDiscovery(t, root)

	called := false
	chooseFlag := func(flag string, options []string) (string, error) {
		called = true
		return "docker", nil
	}

	_, err := resolveAmbiguousWorkspace(discovery, configinit.Input{ScanOnly: true}, false, chooseFlag)
	if err == nil || !strings.Contains(err.Error(), "--stack") {
		t.Fatalf("err = %v, want --stack ambiguity", err)
	}
	if called {
		t.Fatal("chooseFlag must not run when non-interactive")
	}
}

func TestResolveAmbiguousWorkspacePropagatesPromptError(t *testing.T) {
	root := t.TempDir()
	discovery := newAmbiguousDockerDiscovery(t, root)

	chooseFlag := func(flag string, options []string) (string, error) {
		return "", errors.New("boom")
	}

	_, err := resolveAmbiguousWorkspace(discovery, configinit.Input{ScanOnly: true}, true, chooseFlag)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want propagated prompt error", err)
	}
}

func writeAmbiguousDockerPythonProject(t *testing.T, root string) {
	t.Helper()
	digest := "alpine@sha256:" + strings.Repeat("a", 64)
	writeScanProjectFile(t, root, "Dockerfile", "FROM "+digest+"\n")
	writeScanProjectFile(t, root, "requirements.txt", "requests==2.0.0\n")
}

func TestSelectScanConfigurationStackFlagResolvesAmbiguity(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeAmbiguousDockerPythonProject(t, project)

	cfg, selection, err := selectScanConfiguration(scanOptions{directory: project, stack: "docker", nonInteractive: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if selection.Status != "created" || cfg.Workspaces[0].Stack != config.StackDocker {
		t.Fatalf("selection/config = %#v %#v", selection, cfg)
	}
}

func TestSelectScanConfigurationAmbiguousStackNamesWorkingFix(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeAmbiguousDockerPythonProject(t, project)

	_, _, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, "")
	if err == nil || !strings.Contains(err.Error(), "vuelta scan --directory") || !strings.Contains(err.Error(), "--stack") {
		t.Fatalf("ambiguous stack error = %v, want actionable --stack guidance", err)
	}
	if _, statErr := os.Lstat(filepath.Join(project, projectConfigName)); !os.IsNotExist(statErr) {
		t.Fatalf("ambiguous detection created config: %v", statErr)
	}
}

func TestSelectScanConfigurationExplicitStackConflictsWithPersistedValue(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")

	if _, _, err := selectScanConfiguration(scanOptions{directory: project}, ""); err != nil {
		t.Fatal(err)
	}

	_, _, err := selectScanConfiguration(scanOptions{directory: project, stack: "docker"}, "")
	if err == nil || !strings.Contains(err.Error(), "already configured with workspace.stack") {
		t.Fatalf("conflicting --stack error = %v", err)
	}
}

func TestSelectScanConfigurationDriftFailsClosedNonInteractive(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")
	if _, _, err := selectScanConfiguration(scanOptions{directory: project}, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(project, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(project, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	writeScanProjectFile(t, project, "requirements.txt", "requests==2.0.0\n")

	_, _, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, "")
	if err == nil || !strings.Contains(err.Error(), "no longer matches freshly detected") {
		t.Fatalf("drift error = %v", err)
	}
}

func TestDetectStackDriftWarnsWhenInteractiveFailsClosedOtherwise(t *testing.T) {
	root := t.TempDir()
	writeScanProjectFile(t, root, "requirements.txt", "requests==2.0.0\n")
	workspace := config.Workspace{Stack: config.StackNode}

	warning, err := detectStackDrift(workspace, root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warning, "no longer matches freshly detected") {
		t.Fatalf("warning = %q", warning)
	}

	if _, err := detectStackDrift(workspace, root, false); err == nil || !strings.Contains(err.Error(), "no longer matches freshly detected") {
		t.Fatalf("non-interactive drift error = %v", err)
	}
}

func TestDetectStackDriftNoDisagreement(t *testing.T) {
	root := t.TempDir()
	writeScanProjectFile(t, root, "package.json", "{}\n")
	writeScanProjectFile(t, root, "package-lock.json", "{}\n")
	workspace := config.Workspace{Stack: config.StackNode}

	warning, err := detectStackDrift(workspace, root, false)
	if err != nil || warning != "" {
		t.Fatalf("warning = %q, err = %v", warning, err)
	}
}

func writeScanProjectFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
