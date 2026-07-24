package configinit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"gopkg.in/yaml.v3"
)

func TestNewConfigIsValidAndEmpty(t *testing.T) {
	cfg := NewConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate empty config: %v", err)
	}
	if cfg.SchemaVersion != config.CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", cfg.SchemaVersion, config.CurrentSchemaVersion)
	}
	if len(cfg.Workspaces) != 0 {
		t.Fatalf("workspaces = %d, want zero", len(cfg.Workspaces))
	}
}

func TestSchemaMigrationPreservesLegacyConfigAndPermissions(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	data, err := yaml.Marshal(NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(data), "schema_version: 1\n", "", 1)
	legacy = "# keep migration comment\n" + legacy
	if err := os.WriteFile(configPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := PlanSchemaMigration(configPath)
	if err != nil {
		t.Fatalf("PlanSchemaMigration: %v", err)
	}
	if !plan.Changed || !strings.HasPrefix(string(plan.Updated), "schema_version: 1\n# keep migration comment\n") {
		t.Fatalf("migration did not add only the schema header:\n%s", plan.Updated)
	}
	if err := plan.Apply(configPath); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := config.Load(configPath); err != nil {
		t.Fatalf("load migrated config: %v", err)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}

	repeated, err := PlanSchemaMigration(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Changed {
		t.Fatal("current config planned another migration")
	}
}

func TestSchemaMigrationRejectsUnsupportedOrInvalidLegacyConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "unsupported", data: "schema_version: 2\nworkspaces: []\n"},
		{name: "unknown field", data: "unknown_credential: fake-secret-must-not-leak\nworkspaces: []\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := PlanSchemaMigration(path)
			if err == nil {
				t.Fatal("expected migration rejection")
			}
			if strings.Contains(err.Error(), "fake-secret-must-not-leak") {
				t.Fatalf("migration error leaked config value: %v", err)
			}
		})
	}
}

func TestSchemaMigrationTransformsKnownPreVersionFields(t *testing.T) {
	cfg := NewConfig()
	cfg.Workspaces = []config.Workspace{buildNodeWorkspace(t, nodeProject(t), "api")}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	root, err := documentMapping(&document)
	if err != nil {
		t.Fatal(err)
	}
	deleteMappingNode(root, "schema_version")
	vulnerability := mappingValue(root, "vuln_scan")
	deleteMappingNode(vulnerability, "dependency_source")
	enabled, err := encodeNode(true)
	if err != nil {
		t.Fatal(err)
	}
	setMappingNode(vulnerability, "enabled", enabled)
	setMappingString(vulnerability, "tool", "trivy")
	github := mappingValue(root, "github_advisories")
	setMappingNode(github, "enabled", enabled)
	setMappingNode(root, "autofix", &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	setMappingNode(root, "deploy_task", &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	workspace := mappingValue(root, "workspaces").Content[0]
	deleteMappingNode(workspace, "verification")
	setMappingNode(workspace, "test", &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	legacy, err := encodeDocument(&document, data)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSchemaMigration(path)
	if err != nil {
		t.Fatalf("PlanSchemaMigration: %v", err)
	}
	review := strings.Join(plan.Review, "\n")
	for _, wanted := range []string{
		"vuln_scan.tool", "github_advisories.enabled", "parked autofix",
		"parked deploy_task", "verification.state=scan_only",
	} {
		if !strings.Contains(review, wanted) {
			t.Fatalf("migration review lacks %q:\n%s", wanted, review)
		}
	}
	if err := plan.Apply(path); err != nil {
		t.Fatal(err)
	}
	migrated, err := config.Load(path)
	if err != nil {
		t.Fatalf("load migrated config: %v", err)
	}
	if len(migrated.Workspaces) != 1 || migrated.Workspaces[0].Verification.State != config.VerificationScanOnly {
		t.Fatalf("migrated workspaces = %#v", migrated.Workspaces)
	}
}

func TestSchemaMigrationRemovesOnlyRetiredSnapshotStateField(t *testing.T) {
	cfg := NewConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	legacyDir := filepath.Join(t.TempDir(), "legacy-snapshots")
	if err := os.Mkdir(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(legacyDir, "keep.json")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	withRetired := strings.Replace(
		string(data),
		"    snapshot_ttl_hours: 24\n",
		"    snapshot_ttl_hours: 24\n    snapshot_state_dir: "+legacyDir+"\n",
		1,
	)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(withRetired), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSchemaMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed || !strings.Contains(strings.Join(plan.Review, "\n"), "snapshot_state_dir") || strings.Contains(string(plan.Updated), "snapshot_state_dir") {
		t.Fatalf("retired-field migration = review %v\n%s", plan.Review, plan.Updated)
	}
	if err := plan.Apply(path); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("load migrated config: %v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
		t.Fatalf("legacy snapshot contents were touched: %q %v", data, err)
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
