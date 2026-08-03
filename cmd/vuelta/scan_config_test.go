package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

func TestSelectScanConfigurationCreatesAndReusesManifestOnlyNPMProjectConfig(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")

	cfg, selection, err := selectScanConfiguration(scanOptions{directory: project}, filepath.Join("unused", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if selection.Status != "created" || selection.Scope != "project" || !selection.OnboardingChanged || len(cfg.Workspaces) != 1 || cfg.Workspaces[0].Path != project {
		t.Fatalf("selection/config = %#v %#v", selection, cfg)
	}
	if cfg.Workspaces[0].Verification.State != config.VerificationScanOnly {
		t.Fatalf("onboarding verification state = %q, want scan_only", cfg.Workspaces[0].Verification.State)
	}
	if strings.Join(selection.DetectedStacks, ",") != config.StackNode {
		t.Fatalf("created detected stacks = %#v, want [%s]", selection.DetectedStacks, config.StackNode)
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
	if strings.Join(reused.DetectedStacks, ",") != config.StackNode {
		t.Fatalf("reused detected stacks = %#v, want [%s]", reused.DetectedStacks, config.StackNode)
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
	if strings.Join(selection.DetectedStacks, ",") != "docker,python" {
		t.Fatalf("detected stacks = %#v, want [docker python]", selection.DetectedStacks)
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

func TestSelectScanConfigurationTagPinnedDockerfileOnboardsWithoutHandDigest(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "Dockerfile", "FROM node:20-alpine\n")
	writeScanProjectFile(t, project, "compose.yml", "services:\n  app:\n    build: .\n")

	cfg, _, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, "")
	if err != nil {
		t.Fatalf("a tag-pinned Dockerfile with build: . must onboard without a hand-written digest: %v", err)
	}
	if len(cfg.Workspaces) != 1 || cfg.Workspaces[0].DockerImages == nil {
		t.Fatalf("workspace = %#v", cfg.Workspaces)
	}
	images := cfg.Workspaces[0].DockerImages.RuntimeImages
	if len(images) != 1 || images[0] != "node:20-alpine" {
		t.Fatalf("docker_images.runtime_images = %#v, want [node:20-alpine]", images)
	}
	data, err := os.ReadFile(filepath.Join(project, projectConfigName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sha256:") {
		t.Fatalf("onboarding must never write a sha256 digest into .vuelta.yaml:\n%s", data)
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
	if err == nil || !strings.Contains(err.Error(), "remains freshly detected") {
		t.Fatalf("conflicting --stack error = %v", err)
	}
}

func TestSelectScanConfigurationKeepsPersistedNodeWhenGeneratedComposeAddsDockerSignal(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")

	_, created, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	writeScanProjectFile(t, project, "compose.verify.yml", "services:\n  verify:\n    image: node:24-alpine\n")
	writeScanProjectFile(t, project, "Dockerfile", "FROM node:24-alpine\n")

	cfg, reused, err := selectScanConfiguration(scanOptions{
		directory: project, stack: config.StackNode, nonInteractive: true,
	}, "")
	if err != nil {
		t.Fatalf("persisted node must remain valid among docker,node signals: %v", err)
	}
	after, err := os.ReadFile(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workspaces[0].Stack != config.StackNode || strings.Join(reused.DetectedStacks, ",") != "docker,node" {
		t.Fatalf("selection/config = %#v %#v", reused, cfg.Workspaces[0])
	}
	if reused.Status != "reused" || reused.OnboardingChanged || !bytes.Equal(before, after) {
		t.Fatal("valid persisted stack was unexpectedly rewritten")
	}
}

func TestSelectScanConfigurationExplicitStackRepairsGenuineDrift(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")
	if _, _, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(project, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(project, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	writeScanProjectFile(t, project, "requirements.txt", "requests==2.0.0\n")

	cfg, selection, err := selectScanConfiguration(scanOptions{
		directory: project, stack: config.StackPython, nonInteractive: true,
	}, "")
	if err != nil {
		t.Fatalf("repair genuine drift: %v", err)
	}
	if selection.Status != "updated" || !selection.OnboardingChanged || strings.Join(selection.ChangedFiles, ",") != projectConfigName {
		t.Fatalf("selection = %#v", selection)
	}
	workspace := cfg.Workspaces[0]
	if workspace.Stack != config.StackPython || workspace.PackageManager != "requirements" || workspace.Verification.State != config.VerificationScanOnly {
		t.Fatalf("repaired workspace = %#v", workspace)
	}
	persisted, err := config.LoadProject(filepath.Join(project, projectConfigName))
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Workspace.Stack != config.StackPython || persisted.Workspace.PackageManager != "requirements" {
		t.Fatalf("persisted workspace = %#v", persisted.Workspace)
	}
	if _, reused, err := selectScanConfiguration(scanOptions{directory: project, nonInteractive: true}, ""); err != nil || reused.Status != "reused" {
		t.Fatalf("reuse repaired config: selection=%#v err=%v", reused, err)
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
	if err == nil || !strings.Contains(err.Error(), "no longer among freshly detected") {
		t.Fatalf("drift error = %v", err)
	}
}

func TestDetectStackDriftWarnsWhenInteractiveFailsClosedOtherwise(t *testing.T) {
	root := t.TempDir()
	writeScanProjectFile(t, root, "requirements.txt", "requests==2.0.0\n")
	workspace := config.Workspace{Stack: config.StackNode}

	warning, detected, err := detectStackDrift(workspace, root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warning, "no longer among freshly detected") {
		t.Fatalf("warning = %q", warning)
	}
	if strings.Join(detected, ",") != config.StackPython {
		t.Fatalf("detected stacks = %#v, want [%s]", detected, config.StackPython)
	}

	_, _, nonInteractiveErr := detectStackDrift(workspace, root, false)
	if nonInteractiveErr == nil || nonInteractiveErr.Error() != warning {
		t.Fatalf("non-interactive drift error = %v, want same diagnostic as interactive warning %q", nonInteractiveErr, warning)
	}
	if !strings.Contains(warning, "vuelta scan --directory") || !strings.Contains(warning, "--stack python --no-input") {
		t.Fatalf("drift diagnostic does not contain an exact CLI repair: %q", warning)
	}
	if strings.Contains(warning, "edit workspace.stack") || strings.Contains(warning, "remove .vuelta.yaml") {
		t.Fatalf("drift diagnostic still requires manual config repair: %q", warning)
	}
}

func TestDetectStackDriftNoDisagreement(t *testing.T) {
	root := t.TempDir()
	writeScanProjectFile(t, root, "package.json", "{}\n")
	writeScanProjectFile(t, root, "package-lock.json", "{}\n")
	workspace := config.Workspace{Stack: config.StackNode}

	warning, detected, err := detectStackDrift(workspace, root, false)
	if err != nil || warning != "" || strings.Join(detected, ",") != config.StackNode {
		t.Fatalf("warning = %q, detected = %#v, err = %v", warning, detected, err)
	}
}

func TestDetectStackDriftAcceptsPersistedStackWithinMultipleSignals(t *testing.T) {
	root := t.TempDir()
	writeScanProjectFile(t, root, "package.json", "{}\n")
	writeScanProjectFile(t, root, "package-lock.json", "{}\n")
	writeScanProjectFile(t, root, "compose.verify.yml", "services:\n  verify:\n    image: node:24-alpine\n")
	writeScanProjectFile(t, root, "Dockerfile", "FROM node:24-alpine\n")
	workspace := config.Workspace{Stack: config.StackNode}

	warning, detected, err := detectStackDrift(workspace, root, false)
	if err != nil || warning != "" || strings.Join(detected, ",") != "docker,node" {
		t.Fatalf("warning = %q, detected = %#v, err = %v", warning, detected, err)
	}
}

func TestDetectStackDriftWithoutSignalsNamesRecoveryInsteadOfConfigEditing(t *testing.T) {
	root := t.TempDir()
	workspace := config.Workspace{Stack: config.StackNode}

	_, detected, err := detectStackDrift(workspace, root, false)
	if err == nil || len(detected) != 0 || !strings.Contains(err.Error(), "Restore a supported project manifest") {
		t.Fatalf("detected = %#v, err = %v", detected, err)
	}
	if strings.Contains(err.Error(), "edit workspace.stack") || strings.Contains(err.Error(), "remove .vuelta.yaml") {
		t.Fatalf("missing-signal diagnostic requires manual config repair: %v", err)
	}
}

func TestStackRepairGuidanceQuotesDirectoryForShell(t *testing.T) {
	guidance := stackRepairGuidance("/tmp/project's files", []string{config.StackPython})
	want := "--directory '/tmp/project'\"'\"'s files' --stack python --no-input"
	if !strings.Contains(guidance, want) {
		t.Fatalf("guidance = %q, want command containing %q", guidance, want)
	}
}

func TestScanConfigSelectionJSONAddsDetectedStacksWithoutChangingExistingFields(t *testing.T) {
	selection := scanConfigSelection{
		Path:              "/project/.vuelta.yaml",
		Scope:             "project",
		Status:            "reused",
		MachineConfig:     "/machine/config.yaml",
		OnboardingChanged: true,
		ChangedFiles:      []string{".gitignore"},
		DriftWarning:      "drift",
		DetectedStacks:    []string{"docker", "node"},
	}
	data, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"path":"/project/.vuelta.yaml","scope":"project","status":"reused","machine_config":"/machine/config.yaml","onboarding_changed":true,"changed_files":[".gitignore"],"drift_warning":"drift","detected_stacks":["docker","node"]}`
	if string(data) != want {
		t.Fatalf("selection JSON = %s, want %s", data, want)
	}
}

func TestProjectMachineMergeKeepsProjectPolicyAndMachineFileUnchanged(t *testing.T) {
	project, projectPath := onboardVerifyProject(t)
	writeGeneratedVerifyCompose(t, project)
	if err := run([]string{"project", "verify", "approve", "--directory", project, "--yes"}); err != nil {
		t.Fatalf("approve project verification: %v", err)
	}

	machine := configinit.NewConfig()
	machine.Update.ToolchainProfiles = []config.ToolchainProfile{{
		Version: config.ToolchainProfileVersion, ID: "operator-node-npm", Stack: config.StackNode, PackageManager: "npm",
		Runtime: "24", PackageManagerVersion: "11.4.2", Scanner: "ncu", ScannerVersion: "22.2.9",
		Image: "registry.example/scanner@sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64", User: "10001:10001",
		LockFormats: []string{"npm-v3"}, Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: true, ReleaseAge: true},
	}}
	machine.Workspaces = []config.Workspace{{
		Name: "stale-machine-entry", Path: project, Stack: config.StackNode, PackageManager: "npm",
		ToolchainProfile:    "operator-node-npm",
		Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
		AllowedChangedPaths: []string{"package.json", "package-lock.json"},
	}}
	machinePath := filepath.Join(t.TempDir(), "config.yaml")
	if err := configinit.Write(machine, machinePath, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(machinePath)
	if err != nil {
		t.Fatal(err)
	}
	projectPolicy, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}

	effective, selection, err := mergeProjectWithMachinePath(projectPolicy, projectPath, "reused", machinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(effective.Workspaces) != 1 {
		t.Fatalf("effective workspaces = %#v", effective.Workspaces)
	}
	workspace := effective.Workspaces[0]
	if workspace.Path != project || workspace.Name == "stale-machine-entry" || workspace.Verification.State != config.VerificationReady ||
		workspace.ToolchainProfile != "operator-node-npm" {
		t.Fatalf("machine workspace policy leaked into effective project policy: %#v", workspace)
	}
	for _, warning := range configWarnings(effective) {
		if strings.Contains(warning, "scan-only") || strings.Contains(warning, "stale-machine-entry") {
			t.Fatalf("stale machine warning leaked into project selection: %q", warning)
		}
	}
	if selection.Path != projectPath || selection.MachineConfig != machinePath || selection.Scope != "project" {
		t.Fatalf("selection = %#v", selection)
	}
	after, err := os.ReadFile(machinePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("project-local resolution rewrote the machine config")
	}

	updateConfig, err := loadUpdateConfiguration(project, machinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(updateConfig.Workspaces) != 1 || updateConfig.Workspaces[0].Verification.State != config.VerificationReady ||
		updateConfig.Workspaces[0].Name == "stale-machine-entry" {
		t.Fatalf("update selected different effective policy: %#v", updateConfig.Workspaces)
	}
}

func TestSelectScanConfigurationCWDAndDirectoryMatch(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")

	byDirectory, directorySelection, err := selectScanConfiguration(scanOptions{directory: project}, "")
	if err != nil {
		t.Fatal(err)
	}
	previousCurrentDirectory := currentDirectory
	currentDirectory = func() (string, error) { return project, nil }
	t.Cleanup(func() { currentDirectory = previousCurrentDirectory })
	byCWD, cwdSelection, err := selectScanConfiguration(scanOptions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if directorySelection.Path != cwdSelection.Path || directorySelection.MachineConfig != cwdSelection.MachineConfig ||
		directorySelection.Scope != cwdSelection.Scope {
		t.Fatalf("directory selection = %#v, cwd selection = %#v", directorySelection, cwdSelection)
	}
	if len(byDirectory.Workspaces) != 1 || len(byCWD.Workspaces) != 1 ||
		byDirectory.Workspaces[0].Path != byCWD.Workspaces[0].Path ||
		byDirectory.Workspaces[0].Verification.State != byCWD.Workspaces[0].Verification.State {
		t.Fatalf("directory config = %#v, cwd config = %#v", byDirectory.Workspaces, byCWD.Workspaces)
	}
}

func TestProjectMachineMergeNeverMigratesMachineConfig(t *testing.T) {
	project := t.TempDir()
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")
	projectPolicy := &config.ProjectConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		Workspace: config.Workspace{
			Path: ".", Stack: config.StackNode, PackageManager: "npm",
			Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
			AllowedChangedPaths: []string{"package.json", "package-lock.json"},
		},
	}
	machinePath := filepath.Join(t.TempDir(), "legacy.yaml")
	before := []byte("workspaces: []\n")
	if err := os.WriteFile(machinePath, before, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := mergeProjectWithMachinePath(projectPolicy, filepath.Join(project, projectConfigName), "reused", machinePath)
	if err == nil || !strings.Contains(err.Error(), "vuelta config migrate") {
		t.Fatalf("legacy machine config error = %v", err)
	}
	after, readErr := os.ReadFile(machinePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("project-local resolution migrated the machine config")
	}
}

func TestProjectMachineMergeRejectsMachineGitAllowlistFallback(t *testing.T) {
	project := t.TempDir()
	writeScanProjectFile(t, project, "package.json", "{}\n")
	writeScanProjectFile(t, project, "package-lock.json", "{}\n")
	projectPolicy := &config.ProjectConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		Workspace: config.Workspace{
			Path: ".", Stack: config.StackNode, PackageManager: "npm",
			Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
		},
	}
	machine := configinit.NewConfig()
	machine.Git.AllowedChangedPaths = []string{"package.json", "package-lock.json"}
	machinePath := filepath.Join(t.TempDir(), "config.yaml")
	if err := configinit.Write(machine, machinePath, false); err != nil {
		t.Fatal(err)
	}

	_, _, err := mergeProjectWithMachinePath(projectPolicy, filepath.Join(project, projectConfigName), "reused", machinePath)
	if err == nil || !strings.Contains(err.Error(), "git.allowed_changed_paths: allowlist is required") {
		t.Fatalf("machine Git allowlist unexpectedly authorized project policy: %v", err)
	}
}

func writeScanProjectFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
