package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProjectResolvesWorkspaceRelativeToConfig(t *testing.T) {
	project := t.TempDir()
	path := filepath.Join(project, ".vuelta.yaml")
	data := "schema_version: 1\nworkspace:\n  name: api\n  path: .\n  stack: node\n  package_manager: npm\n  verification:\n    version: 1\n    state: scan_only\n  branch: \"\"\n  remote: \"\"\n  allowed_changed_paths: [package.json, package-lock.json]\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := loaded.ResolvedWorkspace(path)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Path != project {
		t.Fatalf("resolved workspace path = %q, want %q", workspace.Path, project)
	}
}

func TestLoadProjectRejectsMachineAuthority(t *testing.T) {
	project := t.TempDir()
	path := filepath.Join(project, ".vuelta.yaml")
	data := "schema_version: 1\ndocker:\n  developer: {}\nworkspace:\n  path: .\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProject(path); err == nil || !strings.Contains(err.Error(), "field docker not found") {
		t.Fatalf("LoadProject error = %v, want strict machine-field rejection", err)
	}
}

func TestLoadProjectAllowsRepositoryReadablePermissions(t *testing.T) {
	project := t.TempDir()
	path := filepath.Join(project, ".vuelta.yaml")
	data := "schema_version: 1\nworkspace:\n  path: .\n  stack: node\n  package_manager: npm\n  verification: {version: 1, state: scan_only}\n  branch: \"\"\n  remote: \"\"\n  allowed_changed_paths: [package.json, package-lock.json]\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProject(path); err != nil {
		t.Fatalf("LoadProject mode 0644: %v", err)
	}
}

func TestValidateWorkspaceDoesNotRequireGit(t *testing.T) {
	project := t.TempDir()
	workspace := Workspace{
		Name: "api", Path: project, Stack: StackNode, PackageManager: "npm",
		Verification:        VerificationProfile{Version: VerificationVersion, State: VerificationScanOnly},
		AllowedChangedPaths: []string{"package.json", "package-lock.json"},
	}
	if err := ValidateWorkspace(workspace); err != nil {
		t.Fatalf("gitless workspace validation: %v", err)
	}
}
