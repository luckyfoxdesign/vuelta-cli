package main

import (
	"bytes"
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
	if selection.Status != "created" || selection.Scope != "project" || len(cfg.Workspaces) != 1 || cfg.Workspaces[0].Path != project {
		t.Fatalf("selection/config = %#v %#v", selection, cfg)
	}
	before, err := os.ReadFile(selection.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte("path: .")) || bytes.Contains(before, []byte("docker:")) || bytes.Contains(before, []byte("snapshot_state_dir")) {
		t.Fatalf("project config contains machine authority:\n%s", before)
	}

	_, reused, err := selectScanConfiguration(scanOptions{directory: project}, filepath.Join("unused", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(selection.Path)
	if err != nil {
		t.Fatal(err)
	}
	if reused.Status != "reused" || !bytes.Equal(before, after) {
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

func writeScanProjectFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
