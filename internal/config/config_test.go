package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLocalPackagePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.yaml")
	if err := os.WriteFile(path, []byte("allowed_packages:\n  - '@scope/package'\nmin_release_age_days: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadLocalPackagePolicy(path)
	if err != nil {
		t.Fatalf("LoadLocalPackagePolicy: %v", err)
	}
	if len(policy.AllowedPackages) != 1 || policy.AllowedPackages[0] != "@scope/package" {
		t.Fatalf("policy = %#v", policy)
	}
}

func TestLocalPackagePolicyRejectsFlagLikePackage(t *testing.T) {
	err := (LocalPackagePolicy{AllowedPackages: []string{"--registry"}}).Validate()
	if err == nil {
		t.Fatal("expected flag-like package rejection")
	}
}

func TestLoadDefaultsAutofixToNoShellTools(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("workspaces: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Autofix.AllowedTools != "Read,Edit,Grep" || cfg.Autofix.MaxTurns != 10 || cfg.Autofix.ClaudeBin != "claude" {
		t.Fatalf("unexpected secure autofix defaults: %+v", cfg.Autofix)
	}
}

func TestValidateProductionWorkerRejectsUnsafeOrIncompleteAdapter(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid := &ProductionWorkerConfig{
		StateDir: "/var/lib/vuelta/state", SourceMode: "signed_queue_file", QueueFile: "/var/lib/vuelta/queue.jsonl", ManifestDir: "/var/lib/vuelta/manifests",
		CandidatePublicKey: key, ManifestPublicKey: key, MaxCandidateAgeMinutes: 60, OperationTimeoutSecond: 120,
		Projects: []ProductionProject{{Name: "api", ImageRepository: "registry.example/vuelta/api", ComposeFile: "/etc/vuelta/api.compose.yml", Service: "api", HealthURL: "https://api.example.com/healthz", SmokeURL: "https://api.example.com/smoke"}},
	}
	if errs := validateProductionWorker(valid); len(errs) != 0 {
		t.Fatalf("valid production worker errors = %v", errs)
	}
	valid.Projects[0].ImageRepository = "registry.example/vuelta/api:latest"
	valid.Projects[0].SmokeURL = "http://api.example.com/smoke"
	if errs := validateProductionWorker(valid); len(errs) == 0 {
		t.Fatal("expected unsafe production adapter to be rejected")
	}
}

func TestValidateRejectsUnsafeTestRunArgument(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Workspaces: []Workspace{{
		Path: dir, Stack: StackDocker,
		Test:         TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test", RunArgs: []string{"--privileged"}},
		DockerImages: &DockerImagesSpec{Files: []string{}, RuntimeImages: []string{"registry.example/test@sha256:" + strings.Repeat("a", 64)}},
	}}, Git: GitConfig{AllowedChangedPaths: []string{"package-lock.json"}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "run_args") {
		t.Fatalf("expected run_args rejection, got %v", err)
	}
}

func TestValidateSecurityConfigRequiresPinnedScannerImages(t *testing.T) {
	validDigest := "scanner@sha256:" + strings.Repeat("a", 64)
	cfg := Config{VulnScan: VulnScanConfig{
		DependencySource: "trivy", Image: validDigest,
		FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24,
		ImageScan: ImageScanConfig{Enabled: true, Tool: "trivy", Image: validDigest},
	}}
	if errs := validateSecurityConfig(cfg); len(errs) != 0 {
		t.Fatalf("valid scanner config errors = %v", errs)
	}
	cfg.VulnScan.ImageScan.Image = "aquasec/trivy:latest"
	if errs := validateSecurityConfig(cfg); len(errs) == 0 || !strings.Contains(errs[0].Error(), "image") {
		t.Fatalf("expected unpinned scanner image rejection, got %v", errs)
	}
}

func TestValidateSecurityConfigRequiresOneCompatibleDependencySource(t *testing.T) {
	validDigest := "scanner@sha256:" + strings.Repeat("a", 64)
	cfg := Config{VulnScan: VulnScanConfig{
		DependencySource: "github-dependabot", FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24,
		ImageScan: ImageScanConfig{Enabled: true, Tool: "trivy", Image: validDigest},
	}}
	if errs := validateSecurityConfig(cfg); len(errs) != 0 {
		t.Fatalf("valid Dependabot config errors = %v", errs)
	}
	cfg.VulnScan.Image = validDigest
	if errs := validateSecurityConfig(cfg); len(errs) == 0 || !strings.Contains(errs[0].Error(), "must be empty") {
		t.Fatalf("expected incompatible local scanner image rejection, got %v", errs)
	}
	cfg.VulnScan.DependencySource = ""
	cfg.VulnScan.Image = ""
	if errs := validateSecurityConfig(cfg); len(errs) == 0 || !strings.Contains(errs[0].Error(), "dependency_source") {
		t.Fatalf("expected missing source rejection, got %v", errs)
	}
}

func TestValidateSecurityConfigConstrainsGithubAdvisories(t *testing.T) {
	base := Config{VulnScan: VulnScanConfig{
		DependencySource: "github-dependabot", FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24,
	}}
	base.GithubAdvisories = GithubAdvisoriesConfig{APIURL: "https://api.github.com", TokenEnv: "GITHUB_TOKEN"}
	if errs := validateSecurityConfig(base); len(errs) != 0 {
		t.Fatalf("valid github_advisories config errors = %v", errs)
	}
	cases := []struct {
		name string
		cfg  GithubAdvisoriesConfig
		want string
	}{
		{"http downgrade", GithubAdvisoriesConfig{APIURL: "http://api.github.com"}, "https"},
		{"userinfo", GithubAdvisoriesConfig{APIURL: "https://user:fake-secret@api.github.com"}, "userinfo"},
		{"unexpected port", GithubAdvisoriesConfig{APIURL: "https://api.github.com:8443"}, "port"},
		{"query", GithubAdvisoriesConfig{APIURL: "https://api.github.com?x=1"}, "query"},
		{"token env", GithubAdvisoriesConfig{TokenEnv: "AWS_SECRET_ACCESS_KEY"}, "token_env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.GithubAdvisories = tc.cfg
			errs := validateSecurityConfig(cfg)
			if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
				t.Fatalf("expected %s rejection, got %v", tc.name, errs)
			}
			for _, err := range errs {
				if strings.Contains(err.Error(), "fake-secret") {
					t.Fatalf("error leaks URL credentials: %v", err)
				}
			}
		})
	}
}

func TestValidateRejectsDuplicateWorkspaceNamesAndCanonicalPaths(t *testing.T) {
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	workspace := Workspace{
		Name: "api", Path: project, Stack: StackNode, PackageManager: "npm",
		Test:                TestProfile{ComposeFile: "compose.yml", Service: "test", RunArgs: []string{"--rm"}},
		AllowedChangedPaths: []string{"package.json"},
	}
	cfg := Config{Workspaces: []Workspace{workspace, workspace}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicates workspaces[0]") || !strings.Contains(err.Error(), "canonical path") {
		t.Fatalf("duplicate identity error = %v", err)
	}
}

func TestUnnamedWorkspaceUsesFallbackWithoutMutation(t *testing.T) {
	workspace := Workspace{Path: "/tmp/example-api"}
	cfg := Config{Workspaces: []Workspace{workspace}}
	warnings := cfg.WorkspaceWarnings()
	if got := WorkspaceName(cfg.Workspaces[0]); got != "example-api" {
		t.Fatalf("fallback name = %q", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "without rewriting") {
		t.Fatalf("warnings = %v", warnings)
	}
	if cfg.Workspaces[0].Name != "" {
		t.Fatal("fallback mutated the loaded workspace")
	}
}
