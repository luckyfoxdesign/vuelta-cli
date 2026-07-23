package config

import (
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
	if err := os.WriteFile(path, []byte("schema_version: 1\nworkspaces: []\n"), 0o600); err != nil {
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

func TestParseRejectsInlineNotificationCredentials(t *testing.T) {
	const secret = "fake-inline-notification-secret"
	for _, data := range []string{
		"schema_version: 1\nnotify:\n  webhook_url: https://hooks.example/" + secret + "\n",
		"schema_version: 1\nnotify:\n  telegram:\n    bot_token: " + secret + "\n",
	} {
		_, err := Parse([]byte(data))
		if err == nil {
			t.Fatal("expected inline credential field to be rejected")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("parse error leaked inline credential: %v", err)
		}
	}
}

func TestParseRequiresCurrentSchemaVersionWithoutLeakingValues(t *testing.T) {
	const secret = "fake-legacy-secret-must-not-appear"
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "missing", data: "legacy_secret: " + secret + "\nworkspaces: []\n", want: "schema_version is missing"},
		{name: "unsupported", data: "schema_version: 2\nlegacy_secret: " + secret + "\n", want: "schema_version 2 is unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse error = %v, want %q", err, test.want)
			}
			if !strings.Contains(err.Error(), "vuelta config init --replace") {
				t.Fatalf("Parse error lacks recovery command: %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("Parse error leaked config value: %v", err)
			}
		})
	}
}

func TestLoadSchemaVersionErrorNamesSelectedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy config.yaml")
	if err := os.WriteFile(path, []byte("workspaces: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "--config PATH") {
		t.Fatalf("Load error = %v, want selected config recovery command", err)
	}
}

func TestValidateNotifyConfigRequiresFixedEnvironmentReferences(t *testing.T) {
	valid := NotifyConfig{
		WebhookURLEnv: NotifyWebhookURLEnv,
		Telegram:      TelegramConfig{BotTokenEnv: NotifyTelegramBotTokenEnv, ChatID: "42"},
	}
	if errs := validateNotifyConfig(valid); len(errs) != 0 {
		t.Fatalf("valid notification config errors = %v", errs)
	}
	valid.WebhookURLEnv = "AWS_SECRET_ACCESS_KEY"
	valid.Telegram.BotTokenEnv = "DATABASE_PASSWORD"
	if errs := validateNotifyConfig(valid); len(errs) != 2 {
		t.Fatalf("arbitrary environment references errors = %v", errs)
	}
	if errs := validateNotifyConfig(NotifyConfig{Telegram: TelegramConfig{ChatID: "42"}}); len(errs) != 1 {
		t.Fatalf("incomplete Telegram config errors = %v", errs)
	}
}

func TestValidateEgressBindsProxyURLToManagedContainer(t *testing.T) {
	valid := EgressConfig{Network: "vuelta-update-egress", ProxyContainer: "vuelta-egress-proxy", ProxyURL: "http://vuelta-egress-proxy:3128"}
	if errs := validateEgress(valid); len(errs) != 0 {
		t.Fatalf("valid egress errors = %v", errs)
	}
	for _, proxyURL := range []string{"http://other:3128", "http://vuelta-egress-proxy:8080"} {
		candidate := valid
		candidate.ProxyURL = proxyURL
		if errs := validateEgress(candidate); len(errs) != 1 {
			t.Fatalf("proxy URL %q errors = %v", proxyURL, errs)
		}
	}
}

func TestNotificationReferencesDoNotAffectSnapshotPolicyHash(t *testing.T) {
	workspace := Workspace{Name: "api", Path: "/projects/api"}
	withoutNotify, err := (Config{}).SnapshotPolicyHash(workspace)
	if err != nil {
		t.Fatal(err)
	}
	withNotify, err := (Config{Notify: NotifyConfig{
		WebhookURLEnv: NotifyWebhookURLEnv,
		Telegram:      TelegramConfig{BotTokenEnv: NotifyTelegramBotTokenEnv, ChatID: "42"},
	}}).SnapshotPolicyHash(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if withNotify != withoutNotify {
		t.Fatal("notification references changed the snapshot policy hash")
	}
}

func TestValidateDockerEndpointRequiresPinnedIdentityAndLocalSocket(t *testing.T) {
	endpoint := &DockerEndpointConfig{Socket: "tcp://attacker.invalid:2375"}
	if errs := validateDockerEndpoint("docker.developer", endpoint, true); len(errs) < 6 {
		t.Fatalf("incomplete endpoint errors = %v", errs)
	}
	endpoint = &DockerEndpointConfig{Socket: "/var/run/docker.sock", ExpectedDaemon: DockerDaemonIdentity{
		ID: "daemon-id", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
		MinimumAPIVersion: "1.44", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
	}}
	if errs := validateDockerEndpoint("docker.developer", endpoint, true); len(errs) != 0 {
		t.Fatalf("valid endpoint errors = %v", errs)
	}
}

func TestValidateRejectsUnsafeVerificationCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Workspaces: []Workspace{{
		Path: dir, Stack: StackDocker,
		Verification: VerificationProfile{Version: VerificationVersion, State: VerificationReady, Steps: []VerificationStep{{
			Name: "test", ComposeFile: "docker-compose.test.yml", Service: "test", Command: []string{"npm", "run", "dev"},
			TimeoutSeconds: 60, Required: true, SuccessExitCodes: []int{0},
		}}},
		DockerImages: &DockerImagesSpec{Files: []string{}, RuntimeImages: []string{"registry.example/test@sha256:" + strings.Repeat("a", 64)}},
	}}, Git: GitConfig{AllowedChangedPaths: []string{"package-lock.json"}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "dev") {
		t.Fatalf("expected unsafe verification command rejection, got %v", err)
	}
}

func TestValidateWorkspaceAllowsManagerlessPythonOnlyForScanOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	workspace := Workspace{
		Path: dir, Stack: StackPython,
		Verification: VerificationProfile{Version: VerificationVersion, State: VerificationScanOnly},
	}
	if errs := validateWorkspace(0, workspace); len(errs) != 0 {
		t.Fatalf("scan-only requirements workspace errors = %v", errs)
	}
	workspace.Verification = VerificationProfile{Version: VerificationVersion, State: VerificationReady}
	errs := validateWorkspace(0, workspace)
	if len(errs) == 0 || !strings.Contains(errorsText(errs), "package_manager") {
		t.Fatalf("update-capable managerless workspace errors = %v", errs)
	}
}

func TestValidateWorkspaceRequiresScanOnlyForRequirementsManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	workspace := Workspace{
		Path: dir, Stack: StackPython, PackageManager: "requirements",
		Verification: VerificationProfile{Version: VerificationVersion, State: VerificationScanOnly},
	}
	if errs := validateWorkspace(0, workspace); len(errs) != 0 {
		t.Fatalf("scan-only requirements workspace errors = %v", errs)
	}
	workspace.Verification = VerificationProfile{Version: VerificationVersion, State: VerificationReady}
	if errs := validateWorkspace(0, workspace); len(errs) == 0 || !strings.Contains(errorsText(errs), "safe mutation contract") {
		t.Fatalf("update-capable requirements workspace errors = %v", errs)
	}
}

func errorsText(errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "\n")
}

func TestPackageVerificationCommandRejectsScriptDriftToWatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"scripts":{"test":"vitest run"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePackageVerificationCommand(dir, []string{"npm", "test"}); err != nil {
		t.Fatalf("safe test script rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"scripts":{"test":"vitest --watch"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePackageVerificationCommand(dir, []string{"npm", "test"}); err == nil || !strings.Contains(err.Error(), "watch") {
		t.Fatalf("watch drift was not rejected: %v", err)
	}
}

func TestVerificationProfileIdentityChangesWithCommandAndTimeout(t *testing.T) {
	workspace := Workspace{Verification: VerificationProfile{Version: VerificationVersion, State: VerificationReady, Steps: []VerificationStep{{
		Name: "test", ComposeFile: "compose.yml", Service: "verify", Command: []string{"go", "test", "./..."},
		TimeoutSeconds: 60, Required: true, SuccessExitCodes: []int{0},
	}}}}
	first, err := VerificationProfileHash(workspace)
	if err != nil {
		t.Fatal(err)
	}
	workspace.Verification.Steps[0].TimeoutSeconds++
	second, err := VerificationProfileHash(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("timeout drift did not change verification identity")
	}
	workspace.Verification.Steps[0].Command = []string{"go", "build", "./..."}
	third, err := VerificationProfileHash(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if second == third {
		t.Fatal("command drift did not change verification identity")
	}
}

func TestValidateRejectsInvalidChangedPathPattern(t *testing.T) {
	t.Parallel()
	cfg := Config{Git: GitConfig{AllowedChangedPaths: []string{`nested\package.json`}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "git.allowed_changed_paths[0]") {
		t.Fatalf("expected invalid Git path pattern rejection, got %v", err)
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
		Verification:        VerificationProfile{Version: VerificationVersion, State: VerificationScanOnly},
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
