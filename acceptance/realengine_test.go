//go:build realengine

package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/testfixture"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"gopkg.in/yaml.v3"
)

const caseTimeout = 12 * time.Minute

const (
	acceptanceEgressNetwork   = "vuelta-acceptance-egress"
	acceptanceEgressContainer = "vuelta-acceptance-egress-proxy"
)

type matrix struct {
	Engine string       `yaml:"engine"`
	Cases  []matrixCase `yaml:"cases"`
}

type matrixCase struct {
	Name              string                  `yaml:"name"`
	FixtureRoot       string                  `yaml:"fixture_root"`
	Fixture           string                  `yaml:"fixture"`
	ScanOnly          bool                    `yaml:"scan_only"`
	MinReleaseAgeDays int                     `yaml:"min_release_age_days"`
	Profile           config.ToolchainProfile `yaml:"profile"`
}

type commandEnvelope struct {
	Results []struct {
		Status          string   `json:"status"`
		SnapshotID      string   `json:"snapshot_id"`
		Vulnerabilities []string `json:"vulnerabilities"`
		InputCategories []string `json:"input_categories"`
		Candidates      []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"candidates"`
		PackageUpdates *struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"package_updates"`
		Stages []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"stages"`
		Toolchain *toolchain.Identity `json:"toolchain"`
		Error     *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"results"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

type dockerVersionIdentity struct {
	ServerVersion   string `json:"server_version"`
	APIVersion      string `json:"api_version"`
	OperatingSystem string `json:"os"`
	Architecture    string `json:"architecture"`
}

type dockerInfoIdentity struct {
	ID              string   `json:"id"`
	SecurityOptions []string `json:"security_options"`
}

func TestRealEngineScanMatrix(t *testing.T) {
	matrixPath := os.Getenv("VUELTA_ACCEPTANCE_MATRIX")
	root := os.Getenv("VUELTA_ACCEPTANCE_ROOT")
	if matrixPath == "" || root == "" {
		t.Skip("manual/networked suite: use scripts/real-engine-acceptance.sh MATRIX")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("[infrastructure] VUELTA_ACCEPTANCE_ROOT must be absolute")
	}
	loaded := loadMatrix(t, matrixPath)
	dockerConfig := checkEngine(t, loaded.Engine)
	binary := buildProductionBinary(t, root)
	for _, testCase := range loaded.Cases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			runCase(t, binary, root, dockerConfig, testCase)
		})
	}
}

func TestRealEngineDockerEndpointIdentity(t *testing.T) {
	configured := checkEngine(t, "").Developer
	executor := dockerexec.New(dockerexec.Options{Endpoint: dockerexec.Endpoint{
		SocketPath: configured.Socket,
		Expected: dockerexec.DaemonIdentity{
			ID: configured.ExpectedDaemon.ID, ServerVersion: configured.ExpectedDaemon.ServerVersion,
			OperatingSystem: configured.ExpectedDaemon.OperatingSystem, Architecture: configured.ExpectedDaemon.Architecture,
			MinimumAPIVersion:       configured.ExpectedDaemon.MinimumAPIVersion,
			RequiredSecurityOptions: append([]string(nil), configured.ExpectedDaemon.RequiredSecurityOptions...),
		},
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := executor.Run(ctx, dockerexec.Request{
		Args:   []string{"version", "--format", `{{.Server.Version}}`},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 1024},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		t.Fatalf("[compatibility] explicit endpoint executor smoke: %v", err)
	}
	if strings.TrimSpace(string(result.Stdout)) != configured.ExpectedDaemon.ServerVersion {
		t.Fatalf("[compatibility] caller command returned an unexpected server version")
	}
}

func TestRealEngineInstalledBootstrapAndAdhocScans(t *testing.T) {
	matrixPath := os.Getenv("VUELTA_ACCEPTANCE_MATRIX")
	root := os.Getenv("VUELTA_ACCEPTANCE_ROOT")
	if matrixPath == "" || root == "" {
		t.Skip("manual/networked suite: use scripts/real-engine-acceptance.sh MATRIX")
	}
	loaded := loadMatrix(t, matrixPath)
	_ = checkEngine(t, loaded.Engine)
	binary := buildProductionBinary(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()
	caseRoot, err := os.MkdirTemp(root, "vuelta-acceptance-case-")
	if err != nil {
		t.Fatalf("[infrastructure] create case directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(caseRoot) })
	project := filepath.Join(caseRoot, "project")
	if err := testfixture.SetupProject(ctx, "/src/testdata/fixtures/projects", "py-requirements-only-cve", project); err != nil {
		t.Fatalf("[infrastructure] prepare fixture: %v", err)
	}
	configPath := filepath.Join(caseRoot, "config", "config.yaml")
	env := append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(caseRoot, "xdg-config"),
		"DOCKER_HOST=tcp://untrusted.invalid:2375", "DOCKER_CONTEXT=untrusted",
		"DOCKER_CONFIG="+filepath.Join(caseRoot, "untrusted-docker-config"),
		"HTTP_PROXY=http://untrusted.invalid:8080", "HTTPS_PROXY=http://untrusted.invalid:8080",
	)
	bootstrap := runJSONInDir(t, ctx, env, caseRoot, "compatibility", binary,
		"environment", "bootstrap", "--socket", "/var/run/docker.sock", "--yes", "--json", "--config", configPath)
	if len(bootstrap.Results) != 1 || bootstrap.Results[0].Status != "trusted" {
		t.Fatalf("[compatibility] bootstrap result = %#v", bootstrap.Results)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("[parsing] load bootstrapped config: %v", err)
	}
	if cfg.Docker == nil || cfg.Docker.Developer == nil || (cfg.Docker.Developer.ExpectedDaemon.Architecture != "amd64" && cfg.Docker.Developer.ExpectedDaemon.Architecture != "arm64") {
		t.Fatalf("[security] bootstrap did not persist a canonical daemon identity")
	}
	// The developer host running this suite may retain the old Compose-created
	// default network, which the installed CLI must correctly reject because it
	// has no ownership labels. Isolate this acceptance invocation without
	// deleting or adopting that external resource.
	cfg.Update.Egress = config.EgressConfig{
		Network: "vuelta-acceptance-bootstrap-egress", ProxyContainer: "vuelta-acceptance-bootstrap-egress-proxy",
		ProxyURL: "http://vuelta-acceptance-bootstrap-egress-proxy:3128",
	}
	writeConfig(t, configPath, cfg)
	vulnerability := runJSONInDir(t, ctx, env, caseRoot, "scanner", binary,
		"scan", "--directory", project, "--execution", "container", "--only", "vulnerabilities", "--json", "--config", configPath)
	if len(vulnerability.Results) != 1 || vulnerability.Results[0].Error != nil || !hasAcceptanceStage(vulnerability.Results[0].Stages, "vulnerability", "succeeded") {
		t.Fatalf("[scanner] installed vulnerability scan = %#v", vulnerability.Results)
	}
	packages := runJSONInDir(t, ctx, env, caseRoot, "scanner", binary,
		"scan", "--directory", project, "--execution", "container", "--only", "packages", "--json", "--config", configPath)
	if len(packages.Results) != 1 || packages.Results[0].Error != nil || len(packages.Results[0].Candidates) == 0 {
		t.Fatalf("[scanner] installed package scan = %#v", packages.Results)
	}
}

func TestRealEngineStandaloneRequirementsVulnerabilityScan(t *testing.T) {
	matrixPath := os.Getenv("VUELTA_ACCEPTANCE_MATRIX")
	root := os.Getenv("VUELTA_ACCEPTANCE_ROOT")
	if matrixPath == "" || root == "" {
		t.Skip("manual/networked suite: use scripts/real-engine-acceptance.sh MATRIX")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("[infrastructure] VUELTA_ACCEPTANCE_ROOT must be absolute")
	}
	loaded := loadMatrix(t, matrixPath)
	dockerConfig := checkEngine(t, loaded.Engine)
	binary := buildProductionBinary(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()
	caseRoot, err := os.MkdirTemp(root, "vuelta-requirements-cve-")
	if err != nil {
		t.Fatalf("[infrastructure] create case directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(caseRoot) })
	project := filepath.Join(caseRoot, "project")
	if err := testfixture.SetupProject(ctx, "/src/testdata/fixtures/projects", "py-requirements-only-cve", project); err != nil {
		t.Fatalf("[infrastructure] prepare fixture: %v", err)
	}

	cfg := configinit.NewConfig()
	cfg.Docker = dockerConfig
	configureAcceptanceEgress(cfg)
	cfg.Update.SnapshotStateDir = filepath.Join(caseRoot, "snapshots")
	configPath := filepath.Join(caseRoot, "config.yaml")
	writeConfig(t, configPath, cfg)
	env := append(os.Environ(), "XDG_CONFIG_HOME="+filepath.Join(caseRoot, "xdg-config"))
	scan := runJSON(t, ctx, env, "scanner", binary, "scan", "--directory", project, "--execution", "container", "--only", "vulnerabilities", "--json", "--config", configPath)
	if len(scan.Results) != 1 {
		t.Fatalf("[parsing] scan results = %#v", scan.Results)
	}
	result := scan.Results[0]
	if result.Error != nil || (result.Status != "clean" && result.Status != "findings") {
		t.Fatalf("[scanner] requirements-only scan result = %#v", result)
	}
	if result.SnapshotID != "" || !containsAcceptance(result.InputCategories, "dependency-input") || !hasAcceptanceStage(result.Stages, "vulnerability", "succeeded") {
		t.Fatalf("[security] requirements-only scan boundaries = %#v", result)
	}
}

func containsAcceptance(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasAcceptanceStage(stages []struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}, name, status string) bool {
	for _, stage := range stages {
		if stage.Name == name && stage.Status == status {
			return true
		}
	}
	return false
}

func loadMatrix(t *testing.T, path string) matrix {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("[infrastructure] read matrix: %v", err)
	}
	var result matrix
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("[infrastructure] parse matrix: %v", err)
	}
	if result.Engine != "docker-desktop" && result.Engine != "docker-engine" {
		t.Fatalf("[infrastructure] engine must be docker-desktop or docker-engine")
	}
	if len(result.Cases) == 0 {
		t.Fatal("[infrastructure] matrix has no cases")
	}
	return result
}

func checkEngine(t *testing.T, expected string) *config.DockerConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	isolatedConfig := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolatedConfig, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("[infrastructure] initialize isolated Docker config: %v", err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		command.Env = []string{"DOCKER_CONFIG=" + isolatedConfig}
		out, err := command.Output()
		if err != nil {
			t.Fatalf("[infrastructure] explicit Docker endpoint is unavailable: %v", err)
		}
		return out
	}
	versionOutput := run("version", "--format", `{"server_version":{{json .Server.Version}},"api_version":{{json .Server.APIVersion}},"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}}}`)
	infoOutput := run("info", "--format", `{"id":{{json .ID}},"security_options":{{json .SecurityOptions}},"name":{{json .Name}}}`)
	var version dockerVersionIdentity
	if err := json.Unmarshal(versionOutput, &version); err != nil {
		t.Fatalf("[infrastructure] decode Docker version identity: %v", err)
	}
	var info struct {
		dockerInfoIdentity
		Name string `json:"name"`
	}
	if err := json.Unmarshal(infoOutput, &info); err != nil {
		t.Fatalf("[infrastructure] decode Docker capability identity: %v", err)
	}
	if info.ID == "" || version.ServerVersion == "" || version.APIVersion == "" || len(info.SecurityOptions) == 0 {
		t.Fatal("[infrastructure] Docker daemon omitted required identity fields")
	}
	architecture, err := dockerexec.NormalizeArchitecture(version.Architecture)
	if err != nil {
		t.Fatalf("[compatibility] Docker architecture: %v", err)
	}
	text := strings.ToLower(info.Name)
	operatingSystem := strings.ToLower(version.OperatingSystem)
	isDesktop := strings.Contains(text, "docker desktop") || strings.Contains(text, "docker-desktop") || strings.Contains(operatingSystem, "docker desktop")
	if expected != "" && (expected == "docker-desktop") != isDesktop {
		t.Fatalf("[infrastructure] matrix expects %s but endpoint reports a different engine", expected)
	}
	return &config.DockerConfig{Developer: &config.DockerEndpointConfig{
		Socket: "/var/run/docker.sock",
		ExpectedDaemon: config.DockerDaemonIdentity{
			ID: info.ID, ServerVersion: version.ServerVersion, OperatingSystem: version.OperatingSystem,
			Architecture: architecture, MinimumAPIVersion: version.APIVersion,
			RequiredSecurityOptions: append([]string(nil), info.SecurityOptions...),
		},
	}}
}

func buildProductionBinary(t *testing.T, root string) string {
	t.Helper()
	dir, err := os.MkdirTemp(root, "vuelta-acceptance-bin-")
	if err != nil {
		t.Fatalf("[infrastructure] create binary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	binary := filepath.Join(dir, "vuelta")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/vuelta")
	command.Dir = "/src"
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("[infrastructure] build production binary: %v: %s", err, output)
	}
	return binary
}

func runCase(t *testing.T, binary, sharedRoot string, dockerConfig *config.DockerConfig, testCase matrixCase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()
	caseRoot, err := os.MkdirTemp(sharedRoot, "vuelta-acceptance-case-")
	if err != nil {
		t.Fatalf("[infrastructure] create case directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(caseRoot) })
	project := filepath.Join(caseRoot, "project")
	fixtureRoot := testCase.FixtureRoot
	if !filepath.IsAbs(fixtureRoot) {
		fixtureRoot = filepath.Join("/src", fixtureRoot)
	}
	if err := testfixture.SetupProject(ctx, fixtureRoot, testCase.Fixture, project); err != nil {
		t.Fatalf("[infrastructure] prepare fixture: %v", err)
	}
	if !testCase.ScanOnly {
		writeVerificationFixture(t, ctx, project, testCase.Profile)
	}
	attachFixtureRemote(t, ctx, caseRoot, project)
	sentinelName := "credentials.acceptance-sentinel"
	if err := os.WriteFile(filepath.Join(project, ".git", "info", "exclude"), []byte(sentinelName+"\n"), 0o600); err != nil {
		t.Fatalf("[infrastructure] exclude sentinel: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, sentinelName), []byte("must-not-enter-scanner-context\n"), 0o600); err != nil {
		t.Fatalf("[infrastructure] create sentinel: %v", err)
	}
	assertClean(t, ctx, project, "before scan")

	// Each case runs its own vuelta config directory so the global update
	// lock (~/.config/vuelta/vuelta.lock) does not collide across cases that
	// run in parallel via t.Parallel().
	xdgConfigHome := filepath.Join(caseRoot, "xdg-config")
	if err := os.MkdirAll(xdgConfigHome, 0o700); err != nil {
		t.Fatalf("[infrastructure] create case config directory: %v", err)
	}
	env := append(os.Environ(), "XDG_CONFIG_HOME="+xdgConfigHome)

	cfg := configinit.NewConfig()
	cfg.Docker = dockerConfig
	configureAcceptanceEgress(cfg)
	cfg.Update.MinReleaseAgeDays = testCase.MinReleaseAgeDays
	cfg.Update.SnapshotStateDir = filepath.Join(caseRoot, "snapshots")
	cfg.Update.ToolchainProfiles = []config.ToolchainProfile{testCase.Profile}
	cfg.Workspaces = []config.Workspace{workspaceForCase(testCase.Name, project, testCase.Profile)}
	configPath := filepath.Join(caseRoot, "config.yaml")
	writeConfig(t, configPath, cfg)

	runJSON(t, ctx, env, "compatibility", binary, "config", "validate", "--json", configPath)
	scan := runJSON(t, ctx, env, "scanner", binary, "scan", "--project", testCase.Name, "--only", "packages", "--json", configPath)
	if testCase.ScanOnly {
		if len(scan.Results) != 1 || scan.Results[0].Status != config.VerificationScanOnly || scan.Results[0].SnapshotID != "" || len(scan.Results[0].Candidates) == 0 {
			t.Fatalf("[scanner] requirements scan did not return scan-only candidates without a snapshot")
		}
		if scan.Results[0].Candidates[0].Kind != "requirements" || scan.Results[0].PackageUpdates == nil || scan.Results[0].PackageUpdates.Reason != "manifest_has_no_safe_mutation_contract" {
			t.Fatalf("[parsing] requirements scan omitted the machine-readable mutation contract")
		}
		if scan.Results[0].Toolchain == nil || scan.Results[0].Toolchain.ProfileID != testCase.Profile.ID {
			t.Fatalf("[parsing] scan output omitted selected profile identity")
		}
		assertClean(t, ctx, project, "after scan-only requirements scan")
		return
	}
	if len(scan.Results) != 1 || scan.Results[0].Status != "ready" || scan.Results[0].SnapshotID == "" {
		message := "scan did not create a ready snapshot"
		if len(scan.Results) == 1 && scan.Results[0].Error != nil {
			message = scan.Results[0].Error.Code + ": " + scan.Results[0].Error.Message
		}
		t.Fatalf("[scanner] %s", message)
	}
	if scan.Results[0].Toolchain == nil || scan.Results[0].Toolchain.ProfileID != testCase.Profile.ID {
		t.Fatalf("[parsing] scan output omitted selected profile identity")
	}

	snapshot, err := (updatesnapshot.Store{Dir: cfg.Update.SnapshotStateDir}).Load(scan.Results[0].SnapshotID)
	if err != nil {
		t.Fatalf("[parsing] load snapshot: %v", err)
	}
	if snapshot.Toolchain.ProfileID != testCase.Profile.ID || snapshot.Toolchain.Image != testCase.Profile.Image {
		t.Fatalf("[parsing] snapshot toolchain identity does not match the selected profile")
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), sentinelName) {
		t.Fatalf("[security] secret-like sentinel entered snapshot identity")
	}

	drifted := *cfg
	drifted.Update = cfg.Update
	drifted.Update.ToolchainProfiles = append([]config.ToolchainProfile(nil), cfg.Update.ToolchainProfiles...)
	drifted.Update.ToolchainProfiles[0].Capabilities.ProjectConfig = !drifted.Update.ToolchainProfiles[0].Capabilities.ProjectConfig
	writeConfig(t, configPath, &drifted)
	runJSONFailure(t, ctx, env, "compatibility", "snapshot", binary, "--config", configPath, "update", "--dry-run", "--yes", "--json", "--", scan.Results[0].SnapshotID)
	writeConfig(t, configPath, cfg)
	runJSON(t, ctx, env, "compatibility", binary, "--config", configPath, "update", "--dry-run", "--yes", "--json", "--", scan.Results[0].SnapshotID)
	assertClean(t, ctx, project, "after update --dry-run")
}

func workspaceForCase(name, project string, profile config.ToolchainProfile) config.Workspace {
	managerFiles := map[string][]string{
		"npm": {"package.json", "package-lock.json"}, "pnpm": {"package.json", "pnpm-lock.yaml"},
		"bun": {"package.json", "bun.lock"}, "poetry": {"pyproject.toml", "poetry.lock"},
		"uv": {"pyproject.toml", "uv.lock"}, "pip-tools": {"requirements.in", "requirements.txt"},
		"requirements": {"requirements.txt"},
	}
	verification := config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationReady, Steps: []config.VerificationStep{{
		Name: "profile-version", ComposeFile: "compose.vuelta-acceptance.yml", Service: "verify",
		Command: []string{profile.Scanner, "--version"}, TimeoutSeconds: 60, Required: true, SuccessExitCodes: []int{0},
	}}}
	if profile.PackageManager == "requirements" {
		verification = config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly}
	}
	return config.Workspace{
		Name: name, Path: project, Stack: profile.Stack, PackageManager: profile.PackageManager,
		ToolchainProfile: profile.ID, Platform: profile.Platform, Branch: "main", Remote: "origin",
		AllowedChangedPaths: managerFiles[profile.PackageManager],
		Verification:        verification,
	}
}

func configureAcceptanceEgress(cfg *config.Config) {
	cfg.Update.Egress = config.EgressConfig{
		Network: acceptanceEgressNetwork, ProxyContainer: acceptanceEgressContainer,
		ProxyURL: "http://" + acceptanceEgressContainer + ":3128", Persistent: true,
	}
}

func writeVerificationFixture(t *testing.T, ctx context.Context, project string, profile config.ToolchainProfile) {
	t.Helper()
	contents := fmt.Sprintf("services:\n  verify:\n    image: %q\n    platform: %s\n    user: %q\n    read_only: true\n    cap_drop: [\"ALL\"]\n    security_opt: [\"no-new-privileges:true\"]\n    cpus: \"1\"\n    mem_limit: 256m\n    pids_limit: 64\n    networks: [testnet]\n    command: [%q, \"--version\"]\nnetworks:\n  testnet:\n    internal: true\n", profile.Image, profile.Platform, profile.User, profile.Scanner)
	path := filepath.Join(project, "compose.vuelta-acceptance.yml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("[infrastructure] write verification fixture: %v", err)
	}
	for _, args := range [][]string{{"add", "compose.vuelta-acceptance.yml"}, {"commit", "-q", "-m", "fixture: real-engine verification"}} {
		command := exec.CommandContext(ctx, "git", args...)
		command.Dir = project
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("[infrastructure] git fixture update: %v: %s", err, output)
		}
	}
}

func attachFixtureRemote(t *testing.T, ctx context.Context, caseRoot, project string) {
	t.Helper()
	remote := filepath.Join(caseRoot, "origin.git")
	initCommand := exec.CommandContext(ctx, "git", "init", "-q", "--bare", "--initial-branch=main", remote)
	if output, err := initCommand.CombinedOutput(); err != nil {
		t.Fatalf("[infrastructure] initialize fixture remote: %v: %s", err, output)
	}
	for _, args := range [][]string{{"remote", "add", "origin", remote}, {"push", "-q", "--set-upstream", "origin", "main"}} {
		command := exec.CommandContext(ctx, "git", args...)
		command.Dir = project
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("[infrastructure] configure fixture remote: %v: %s", err, output)
		}
	}
}

func writeConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("[compatibility] generated config is invalid: %v", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("[parsing] encode config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("[infrastructure] write config: %v", err)
	}
}

func runJSON(t *testing.T, ctx context.Context, env []string, category, binary string, args ...string) commandEnvelope {
	return runJSONInDir(t, ctx, env, "", category, binary, args...)
}

func runJSONInDir(t *testing.T, ctx context.Context, env []string, dir, category, binary string, args ...string) commandEnvelope {
	t.Helper()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = env
	command.Dir = dir
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err != nil {
		t.Fatalf("[%s] command failed: %s", category, failureMessage(stdout.Bytes(), stderr.String(), err))
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("[parsing] decode command JSON: %v", err)
	}
	return envelope
}

func runJSONFailure(t *testing.T, ctx context.Context, env []string, category, contains, binary string, args ...string) {
	t.Helper()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err == nil {
		t.Fatalf("[%s] command unexpectedly succeeded", category)
	}
	message := failureMessage(stdout.Bytes(), stderr.String(), err)
	if !strings.Contains(strings.ToLower(message), strings.ToLower(contains)) {
		t.Fatalf("[%s] failure %q does not contain %q", category, message, contains)
	}
}

func failureMessage(stdout []byte, stderr string, commandErr error) string {
	var envelope commandEnvelope
	if json.Unmarshal(stdout, &envelope) == nil {
		for _, result := range envelope.Results {
			if result.Error != nil {
				return result.Error.Code + ": " + result.Error.Message
			}
		}
		if len(envelope.Errors) > 0 {
			return envelope.Errors[0].Code + ": " + envelope.Errors[0].Message
		}
	}
	if strings.TrimSpace(stderr) != "" {
		return strings.TrimSpace(stderr)
	}
	var exit *exec.ExitError
	if errors.As(commandErr, &exit) {
		return fmt.Sprintf("exit %d", exit.ExitCode())
	}
	return commandErr.Error()
}

func assertClean(t *testing.T, ctx context.Context, project, phase string) {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=all")
	command.Dir = project
	output, err := command.Output()
	if err != nil {
		t.Fatalf("[infrastructure] inspect worktree %s: %v", phase, err)
	}
	if strings.TrimSpace(string(output)) != "" {
		t.Fatalf("[security] worktree is dirty %s", phase)
	}
}

func TestMain(m *testing.M) {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "real-engine acceptance must run in the Docker test image")
		os.Exit(2)
	}
	code := m.Run()
	if err := cleanupAcceptanceEgress(); err != nil {
		fmt.Fprintf(os.Stderr, "real-engine acceptance egress cleanup: %v\n", err)
		code = 1
	}
	if err := cleanupAcceptanceRoot(os.Getenv("VUELTA_ACCEPTANCE_ROOT")); err != nil {
		fmt.Fprintf(os.Stderr, "real-engine acceptance cleanup: %v\n", err)
		code = 1
	}
	os.Exit(code)
}

func cleanupAcceptanceEgress() error {
	configDir, err := os.MkdirTemp("", "vuelta-acceptance-docker-config-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(configDir) }()
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		return err
	}
	run := func(args ...string) ([]byte, error) {
		command := exec.Command("docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		command.Env = []string{"DOCKER_CONFIG=" + configDir, "HOME=" + configDir, "TMPDIR=" + configDir}
		return command.Output()
	}
	ownerFormat := `{{index .Config.Labels "com.luckyfoxdesign.vuelta.owner"}}`
	if owner, inspectErr := run("container", "inspect", "--format", ownerFormat, acceptanceEgressContainer); inspectErr == nil {
		if strings.TrimSpace(string(owner)) != "managed-egress" {
			return errors.New("refusing to remove acceptance proxy without the Vuelta ownership label")
		}
		if _, err := run("container", "rm", "--force", acceptanceEgressContainer); err != nil {
			return fmt.Errorf("remove acceptance proxy: %w", err)
		}
	}
	networkOwnerFormat := `{{index .Labels "com.luckyfoxdesign.vuelta.owner"}}`
	if owner, inspectErr := run("network", "inspect", "--format", networkOwnerFormat, acceptanceEgressNetwork); inspectErr == nil {
		if strings.TrimSpace(string(owner)) != "managed-egress" {
			return errors.New("refusing to remove acceptance network without the Vuelta ownership label")
		}
		if _, err := run("network", "rm", acceptanceEgressNetwork); err != nil {
			return fmt.Errorf("remove acceptance network: %w", err)
		}
	}
	return nil
}

func cleanupAcceptanceRoot(root string) error {
	if root == "" {
		return nil
	}
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "vuelta-real-engine.") {
		return errors.New("refusing to clean an unrecognized acceptance root")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	allowed := []string{
		"vuelta-acceptance-bin-", "vuelta-acceptance-case-", "vuelta-compose-",
		"vuelta-docker-config-", "vuelta-git-state-", "vuelta-landing-", "vuelta-sandbox-",
	}
	for _, entry := range entries {
		approved := false
		for _, prefix := range allowed {
			if strings.HasPrefix(entry.Name(), prefix) {
				approved = true
				break
			}
		}
		if !approved || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to clean unexpected acceptance entry %q", entry.Name())
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
