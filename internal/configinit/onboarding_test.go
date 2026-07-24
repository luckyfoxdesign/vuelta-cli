package configinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAutoCreateRootBoundaries(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	temp := filepath.Join(base, "tmp")
	configDir := filepath.Join(home, ".config")
	cacheDir := filepath.Join(home, ".cache")
	system := filepath.Join(base, "system")
	for _, path := range []string{home, temp, configDir, cacheDir, system, filepath.Join(home, "project"), filepath.Join(temp, "project")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	environment := PathEnvironment{
		GOOS: "linux", HomeDir: home, TempDir: temp, ConfigDir: configDir,
		CacheDir: cacheDir, SystemDirs: []string{system},
	}
	for _, path := range []string{home, temp, configDir, filepath.Join(cacheDir, "project"), system} {
		if err := ValidateAutoCreateRoot(path, path, environment); err == nil {
			t.Fatalf("unsafe root %s was accepted", path)
		}
	}
	for _, path := range []string{filepath.Join(home, "project"), filepath.Join(temp, "project")} {
		if err := ValidateAutoCreateRoot(path, path, environment); err != nil {
			t.Fatalf("project subdirectory %s was rejected: %v", path, err)
		}
	}
}

func TestValidateAutoCreateRootRejectsSelectedSymlink(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAutoCreateRoot(link, project, PathEnvironment{}); err == nil {
		t.Fatal("symlink-selected project was accepted")
	}
}

func TestDetectGitlessNodeProject(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "package.json", "{}\n")
	writeProjectFile(t, project, "package-lock.json", "{}\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := discovery.BuildWorkspace(Input{ScanOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Stack != "node" || workspace.PackageManager != "npm" || workspace.Branch != "" || workspace.Remote != "" {
		t.Fatalf("gitless workspace = %#v", workspace)
	}
}

func TestDetectGitlessComposeProject(t *testing.T) {
	project := t.TempDir()
	digest := "registry.example/app@sha256:" + strings.Repeat("a", 64)
	writeProjectFile(t, project, "compose.yaml", "services:\n  app:\n    image: "+digest+"\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := discovery.BuildWorkspace(Input{ScanOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Stack != "docker" || workspace.DockerImages == nil ||
		len(workspace.DockerImages.Files) != 1 || workspace.DockerImages.Files[0] != "compose.yaml" {
		t.Fatalf("compose workspace = %#v", workspace)
	}
}
