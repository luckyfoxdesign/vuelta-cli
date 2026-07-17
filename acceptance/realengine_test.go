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
	"github.com/luckyfoxdesign/vuelta/internal/testfixture"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"gopkg.in/yaml.v3"
)

const caseTimeout = 12 * time.Minute

type matrix struct {
	Engine string       `yaml:"engine"`
	Cases  []matrixCase `yaml:"cases"`
}

type matrixCase struct {
	Name              string                  `yaml:"name"`
	FixtureRoot       string                  `yaml:"fixture_root"`
	Fixture           string                  `yaml:"fixture"`
	MinReleaseAgeDays int                     `yaml:"min_release_age_days"`
	Profile           config.ToolchainProfile `yaml:"profile"`
}

type commandEnvelope struct {
	Results []struct {
		Status     string              `json:"status"`
		SnapshotID string              `json:"snapshot_id"`
		Toolchain  *toolchain.Identity `json:"toolchain"`
		Error      *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"results"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
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
	checkEngine(t, loaded.Engine)
	binary := buildProductionBinary(t, root)
	for _, testCase := range loaded.Cases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			runCase(t, binary, root, testCase)
		})
	}
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

func checkEngine(t *testing.T, expected string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", `{{json .}}`).Output()
	if err != nil {
		t.Fatalf("[infrastructure] Docker endpoint is unavailable: %v", err)
	}
	text := strings.ToLower(string(out))
	isDesktop := strings.Contains(text, "docker desktop")
	if (expected == "docker-desktop") != isDesktop {
		t.Fatalf("[infrastructure] matrix expects %s but endpoint reports a different engine", expected)
	}
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

func runCase(t *testing.T, binary, sharedRoot string, testCase matrixCase) {
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
	writeVerificationFixture(t, ctx, project, testCase.Profile)
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
	cfg.Update.MinReleaseAgeDays = testCase.MinReleaseAgeDays
	cfg.Update.SnapshotStateDir = filepath.Join(caseRoot, "snapshots")
	cfg.Update.ToolchainProfiles = []config.ToolchainProfile{testCase.Profile}
	cfg.Workspaces = []config.Workspace{workspaceForCase(testCase.Name, project, testCase.Profile)}
	configPath := filepath.Join(caseRoot, "config.yaml")
	writeConfig(t, configPath, cfg)

	runJSON(t, ctx, env, "compatibility", binary, "config", "validate", "--json", configPath)
	unavailable := *cfg
	unavailable.Update = cfg.Update
	unavailable.Update.Egress.Network = "vuelta-acceptance-missing-network"
	writeConfig(t, configPath, &unavailable)
	runJSONFailure(t, ctx, env, "infrastructure", "egress policy unavailable", binary, "scan", "--project", testCase.Name, "--only", "packages", "--json", configPath)
	writeConfig(t, configPath, cfg)
	scan := runJSON(t, ctx, env, "scanner", binary, "scan", "--project", testCase.Name, "--only", "packages", "--json", configPath)
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
	}
	return config.Workspace{
		Name: name, Path: project, Stack: profile.Stack, PackageManager: profile.PackageManager,
		ToolchainProfile: profile.ID, Platform: profile.Platform, Branch: "main", Remote: "origin",
		AllowedChangedPaths: managerFiles[profile.PackageManager],
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationReady, Steps: []config.VerificationStep{{
			Name: "profile-version", ComposeFile: "compose.vuelta-acceptance.yml", Service: "verify",
			Command: []string{profile.Scanner, "--version"}, TimeoutSeconds: 60, Required: true, SuccessExitCodes: []int{0},
		}}},
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
	t.Helper()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = env
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
	if err := cleanupAcceptanceRoot(os.Getenv("VUELTA_ACCEPTANCE_ROOT")); err != nil {
		fmt.Fprintf(os.Stderr, "real-engine acceptance cleanup: %v\n", err)
		code = 1
	}
	os.Exit(code)
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
