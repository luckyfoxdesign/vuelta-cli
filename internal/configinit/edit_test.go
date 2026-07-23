package configinit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestNewConfigIsValidAndEmpty(t *testing.T) {
	cfg := NewConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate empty config: %v", err)
	}
	if len(cfg.Workspaces) != 0 {
		t.Fatalf("workspaces = %d, want zero", len(cfg.Workspaces))
	}
}

func TestWorkspaceEditPreservesCommentsPermissionsAndIsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := Write(NewConfig(), configPath, false); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	commented := append([]byte("# keep this header\n"), original...)
	commented = []byte(strings.Replace(string(commented), "notify:\n", "notify: # keep this inline comment\n", 1))
	if err := os.WriteFile(configPath, commented, 0o600); err != nil {
		t.Fatal(err)
	}

	workspace := buildNodeWorkspace(t, nodeProject(t), "api")
	plan, err := PlanWorkspaceAdd(configPath, workspace)
	if err != nil {
		t.Fatalf("PlanWorkspaceAdd: %v", err)
	}
	if !plan.Changed || !strings.Contains(plan.Diff(configPath), "+    - name: api") {
		t.Fatalf("unexpected diff:\n%s", plan.Diff(configPath))
	}
	if err := plan.Apply(configPath); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	updated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "# keep this header") || !strings.Contains(string(updated), "# keep this inline comment") {
		t.Fatalf("comments were not preserved:\n%s", updated)
	}
	if strings.Index(string(updated), "notify:") > strings.Index(string(updated), "vuln_scan:") {
		t.Fatal("unrelated top-level key order changed")
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}

	repeated, err := PlanWorkspaceAdd(configPath, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Changed {
		t.Fatal("identical repeated addition planned a write")
	}
}

func TestWorkspaceEditRejectsNamePathAndSettingsConflicts(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := Write(NewConfig(), configPath, false); err != nil {
		t.Fatal(err)
	}
	firstProject := nodeProject(t)
	first := buildNodeWorkspace(t, firstProject, "api")
	plan, err := PlanWorkspaceAdd(configPath, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(configPath); err != nil {
		t.Fatal(err)
	}
	beforeConflicts, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	second := buildNodeWorkspace(t, nodeProject(t), "api")
	if _, err := PlanWorkspaceAdd(configPath, second); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("name conflict error = %v", err)
	}
	pathConflict := first
	pathConflict.Name = "other"
	if _, err := PlanWorkspaceAdd(configPath, pathConflict); err == nil || !strings.Contains(err.Error(), "already configured as") {
		t.Fatalf("path conflict error = %v", err)
	}
	settingsConflict := first
	settingsConflict.Remote = "upstream"
	if _, err := PlanWorkspaceAdd(configPath, settingsConflict); err == nil || !strings.Contains(err.Error(), "different settings") {
		t.Fatalf("settings conflict error = %v", err)
	}
	afterConflicts, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterConflicts) != string(beforeConflicts) {
		t.Fatal("a rejected project conflict modified the config")
	}
}

func TestWorkspaceEditPersistsLegacyNameWithoutOtherRewrites(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	workspace := buildNodeWorkspace(t, nodeProject(t), "api")
	cfg := NewConfig()
	cfg.Workspaces = []config.Workspace{workspace}
	if err := Write(cfg, configPath, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(
		string(data),
		"    - name: api\n      path: "+workspace.Path,
		"    - path: "+workspace.Path,
		1,
	)
	if legacy == string(data) {
		t.Fatalf("could not remove workspace name from fixture:\n%s", data)
	}
	if err := os.WriteFile(configPath, []byte("# legacy comment\n"+legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanWorkspaceAdd(configPath, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed {
		t.Fatal("legacy workspace name was not planned for persistence")
	}
	if err := plan.Apply(configPath); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "# legacy comment") || !strings.Contains(string(updated), "name: api") {
		t.Fatalf("legacy migration output:\n%s", updated)
	}
}

func TestWorkspaceEditRejectsUnsafeDestinations(t *testing.T) {
	workspace := buildNodeWorkspace(t, nodeProject(t), "api")
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.yaml")
		if err := Write(NewConfig(), target, false); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "config.yaml")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := PlanWorkspaceAdd(link, workspace); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink error = %v", err)
		}
	})
	t.Run("broad permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := Write(NewConfig(), path, false); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := PlanWorkspaceAdd(path, workspace); err == nil || !strings.Contains(err.Error(), "broader than 0600") {
			t.Fatalf("permission error = %v", err)
		}
	})
}

func TestWorkspaceEditAtomicRenameFailureLeavesOriginal(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := Write(NewConfig(), configPath, false); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	workspace := buildNodeWorkspace(t, nodeProject(t), "api")
	plan, err := PlanWorkspaceAdd(configPath, workspace)
	if err != nil {
		t.Fatal(err)
	}
	previousRename := atomicRename
	atomicRename = func(_, _ string) error { return errors.New("injected rename failure") }
	t.Cleanup(func() { atomicRename = previousRename })
	if err := plan.Apply(configPath); err == nil || !strings.Contains(err.Error(), "injected rename failure") {
		t.Fatalf("Apply error = %v", err)
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("atomic failure modified the original config")
	}
}

func TestDockerBootstrapCreatesOrPreservesProtectedConfig(t *testing.T) {
	endpoint := config.DockerEndpointConfig{
		Socket: "/approved/docker.sock",
		ExpectedDaemon: config.DockerDaemonIdentity{
			ID: "daemon-id", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
			MinimumAPIVersion: "1.49", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
		},
	}
	t.Run("create", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		plan, err := PlanDockerBootstrap(path, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Changed || plan.Exists {
			t.Fatalf("plan = %#v", plan)
		}
		if err := plan.Apply(path); err != nil {
			t.Fatal(err)
		}
		loaded, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Docker == nil || loaded.Docker.Developer == nil || loaded.Docker.Developer.ExpectedDaemon.Architecture != "arm64" {
			t.Fatalf("Docker endpoint = %#v", loaded.Docker)
		}
	})
	t.Run("preserve", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		cfg := NewConfig()
		cfg.Git.PushMode = "direct_branch"
		if err := Write(cfg, path, false); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append([]byte("# retained comment\n"), data...), 0o600); err != nil {
			t.Fatal(err)
		}
		plan, err := PlanDockerBootstrap(path, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if err := plan.Apply(path); err != nil {
			t.Fatal(err)
		}
		updated, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(updated), "# retained comment") || !strings.Contains(string(updated), "push_mode: direct_branch") {
			t.Fatalf("bootstrap rewrote unrelated YAML:\n%s", updated)
		}
		repeated, err := PlanDockerBootstrap(path, endpoint)
		if err != nil || repeated.Changed {
			t.Fatalf("repeated bootstrap = changed %v, error %v", repeated.Changed, err)
		}
	})
}

func buildNodeWorkspace(t *testing.T, project, name string) config.Workspace {
	t.Helper()
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := discovery.BuildWorkspace(Input{Name: name, Branch: "main", Remote: "origin"})
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}
