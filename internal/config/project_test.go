package config

import (
	"bytes"
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

func TestLoadProjectNormalizesLegacyDockerfileCaseAliasesInMemory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM node:22-alpine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".vuelta.yaml")
	data := []byte(`schema_version: 1
workspace:
  name: legacy-docker
  path: .
  stack: docker
  package_manager: ""
  verification:
    version: 1
    state: scan_only
  branch: main
  remote: origin
  allowed_changed_paths:
    - Dockerfile
    - dockerfile
  docker_images:
    files:
      - Dockerfile
      - dockerfile
    runtime_images:
      - node:22-alpine
    platforms:
      - linux/amd64
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	project, err := LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(project.Workspace.DockerImages.Files, ","); got != "Dockerfile" {
		t.Fatalf("docker files = %q, want exact on-disk spelling", got)
	}
	if got := strings.Join(project.Workspace.AllowedChangedPaths, ","); got != "Dockerfile" {
		t.Fatalf("allowed paths = %q, want exact on-disk spelling", got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, data) {
		t.Fatal("loading legacy policy rewrote the project config")
	}
}

func TestLegacyDockerfileCaseNormalizationPreservesTwoPhysicalFiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Dockerfile", "dockerfile"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("FROM node:22-alpine\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := Workspace{
		AllowedChangedPaths: []string{"Dockerfile", "dockerfile"},
		DockerImages:        &DockerImagesSpec{Files: []string{"Dockerfile", "dockerfile"}},
	}
	if err := normalizeLegacyDockerfileCaseAliases(&workspace, root); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(workspace.DockerImages.Files, ","); got != "Dockerfile,dockerfile" {
		t.Fatalf("docker files = %q, want both physical files", got)
	}
	if got := strings.Join(workspace.AllowedChangedPaths, ","); got != "Dockerfile,dockerfile" {
		t.Fatalf("allowed paths = %q, want both physical files", got)
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
