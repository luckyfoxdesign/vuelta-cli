package configinit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestDetectOnlyInspectsSelectedProjectRoot(t *testing.T) {
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(parent, "selected")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, project, "compose.yml", "services:\n  test: {}\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(discovery.Stacks) != 0 {
		t.Fatalf("stacks = %v; detector must not inspect parent", discovery.Stacks)
	}
}

func TestDetectRecordsTagIntentAndExcludesStageAliasesAndScratch(t *testing.T) {
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, project, "Dockerfile", strings.Join([]string{
		"FROM node:20-alpine AS builder",
		"RUN echo build",
		"FROM builder AS test",
		"FROM scratch",
		"COPY --from=builder /app /app",
		"",
	}, "\n"))
	discovery, err := Detect(project)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(discovery.RuntimeImages) != 1 || discovery.RuntimeImages[0] != "node:20-alpine" {
		t.Fatalf("runtime images = %#v, want only the external tag reference", discovery.RuntimeImages)
	}
}

func TestBuildValidNodeConfigAndWritePermissions(t *testing.T) {
	project := nodeProject(t)
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := discovery.Build(Input{Branch: "main", Remote: "origin"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := strings.Join(cfg.Workspaces[0].AllowedChangedPaths, ","); got != "npm-shrinkwrap.json,package-lock.json,package.json" {
		t.Fatalf("default root-only allowed paths = %q", got)
	}
	if len(cfg.Update.Images) != 0 || len(cfg.Update.Tools) != 0 || len(cfg.Update.ToolchainProfiles) != 0 {
		t.Fatalf("config init seeded legacy scanner pins: %#v", cfg.Update)
	}
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	if err := Write(cfg, path, false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %04o, want 0600", got)
	}
	if err := Write(cfg, path, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Write without replace error = %v, want no-overwrite error", err)
	}
	if err := Write(cfg, path, true); err != nil {
		t.Fatalf("Write with replace: %v", err)
	}
}

func TestDetectManifestOnlyNPMAndRejectsAmbiguousOrMalformedInputs(t *testing.T) {
	t.Parallel()
	t.Run("manifest only", func(t *testing.T) {
		root := t.TempDir()
		writeProjectFile(t, root, "package.json", `{"name":"demo"}`)
		discovery, err := Detect(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(discovery.Stacks) != 1 || discovery.Stacks[0] != config.StackNode ||
			len(discovery.PackageManagers[config.StackNode]) != 1 ||
			discovery.PackageManagers[config.StackNode][0] != "npm" {
			t.Fatalf("discovery = %#v", discovery)
		}
	})
	t.Run("ambiguous npm locks", func(t *testing.T) {
		root := t.TempDir()
		writeProjectFile(t, root, "package.json", `{"name":"demo"}`)
		writeProjectFile(t, root, "package-lock.json", `{"lockfileVersion":3}`)
		writeProjectFile(t, root, "npm-shrinkwrap.json", `{"lockfileVersion":3}`)
		if _, err := Detect(root); err == nil || !strings.Contains(err.Error(), "both package-lock.json") {
			t.Fatalf("Detect() error = %v", err)
		}
	})
	t.Run("malformed manifest", func(t *testing.T) {
		root := t.TempDir()
		writeProjectFile(t, root, "package.json", `{`)
		if _, err := Detect(root); err == nil || !strings.Contains(err.Error(), "parse package.json") {
			t.Fatalf("Detect() error = %v", err)
		}
	})
}

func TestDetectRequirementsOnlyProjectAsScanOnly(t *testing.T) {
	project := filepath.Join(t.TempDir(), "requirements-project")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, project, "requirements.txt", "Requests[socks]==2.31.0\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := discovery.BuildWorkspace(Input{Branch: "main", Remote: "origin"})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Stack != "python" || workspace.PackageManager != "requirements" || workspace.Verification.State != "scan_only" {
		t.Fatalf("workspace = %#v", workspace)
	}
	if got := strings.Join(workspace.AllowedChangedPaths, ","); got != "requirements.txt" {
		t.Fatalf("allowed paths = %q", got)
	}
}

func TestRequirementsInTakesPrecedenceOverRequirementsOnlyDetection(t *testing.T) {
	project := filepath.Join(t.TempDir(), "pip-tools-project")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, project, "requirements.in", "requests==2.31.0\n")
	writeProjectFile(t, project, "requirements.txt", "requests==2.31.0\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(discovery.PackageManagers["python"], ","); got != "pip-tools" {
		t.Fatalf("python managers = %q", got)
	}
}

func TestManagedPythonLockTakesPrecedenceOverExportedRequirements(t *testing.T) {
	project := filepath.Join(t.TempDir(), "poetry-project")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, project, "pyproject.toml", "[project]\nname = \"example\"\n")
	writeProjectFile(t, project, "poetry.lock", "package = []\n")
	writeProjectFile(t, project, "requirements.txt", "requests==2.31.0\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(discovery.PackageManagers["python"], ","); got != "poetry" {
		t.Fatalf("python managers = %q", got)
	}
}

func TestBuildRejectsPathsOutsideSelectedProject(t *testing.T) {
	project := nodeProject(t)
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	_, err = discovery.Build(Input{Branch: "main", Remote: "origin", VerificationNames: []string{"unknown"}})
	if err == nil || !strings.Contains(err.Error(), "declarative verification candidate") {
		t.Fatalf("unknown verification candidate error = %v", err)
	}
	for _, pattern := range []string{"../secrets", `nested\package.json`, "C:/package.json", "nested/../package.json", "**/package.json"} {
		_, err = discovery.Build(Input{Branch: "main", Remote: "origin", AllowedPaths: []string{pattern}})
		if err == nil || !strings.Contains(err.Error(), "git pattern") {
			t.Fatalf("invalid allow path %q error = %v", pattern, err)
		}
	}
}

func TestBuildRequiresFlagsForAmbiguousDetection(t *testing.T) {
	project := nodeProject(t)
	writeProjectFile(t, project, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	_, err = discovery.Build(Input{Branch: "main", Remote: "origin"})
	var missing *MissingValueError
	if !errors.As(err, &missing) || missing.Flag != "--package-manager" {
		t.Fatalf("Build error = %v, want missing package manager", err)
	}
}

func TestBuildWorkspaceRejectsBunBeforeOnboarding(t *testing.T) {
	project := nodeProject(t)
	writeProjectFile(t, project, "bun.lock", "[lockfile]\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	_, err = discovery.BuildWorkspace(Input{PackageManager: "bun", Branch: "main", Remote: "origin"})
	if err == nil || !strings.Contains(err.Error(), "use npm or pnpm") {
		t.Fatalf("bun onboarding error = %v", err)
	}
}

func TestDetectDoesNotOfferSingleDevServerAsVerification(t *testing.T) {
	project := nodeProject(t)
	writeProjectFile(t, project, "package.json", `{"scripts":{"build":"vite build"}}`+"\n")
	writeProjectFile(t, project, "compose.yml", "services:\n  s_svelteapp:\n    command: npm i && npm run dev\n")
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovery.VerificationCandidates) != 0 {
		t.Fatalf("dev server candidates = %#v, want none", discovery.VerificationCandidates)
	}
	workspace, err := discovery.BuildWorkspace(Input{Branch: "main", Remote: "origin"})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Verification.State != "scan_only" {
		t.Fatalf("verification state = %q, want scan_only", workspace.Verification.State)
	}
}

func TestDetectOffersDedicatedVerificationCompose(t *testing.T) {
	project := nodeProject(t)
	writeProjectFile(t, project, "package.json", `{"scripts":{"build":"vite build","dev":"vite dev"}}`+"\n")
	writeProjectFile(t, project, "compose.yml", "services:\n  s_svelteapp:\n    command: npm i && npm run dev\n")
	writeProjectFile(t, project, "compose.verify.yml", validVerificationCompose("verify"))

	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovery.VerificationCandidates) != 1 || discovery.VerificationCandidates[0].ComposeFile != "compose.verify.yml" {
		t.Fatalf("verification candidates = %#v, want dedicated compose file", discovery.VerificationCandidates)
	}
	workspace, err := discovery.BuildWorkspace(Input{Branch: "main", Remote: "origin"})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Verification.State != "ready" || len(workspace.Verification.Steps) != 1 {
		t.Fatalf("verification profile = %#v", workspace.Verification)
	}
}

func TestBuildExplicitMultiStepVerificationFromDeclarativeMetadata(t *testing.T) {
	project := nodeProject(t)
	writeProjectFile(t, project, "package.json", `{"scripts":{"test":"vitest run","build":"vite build","dev":"vite dev"}}`+"\n")
	writeProjectFile(t, project, "compose.yml", validVerificationCompose("verify"))
	discovery, err := Detect(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovery.VerificationCandidates) != 2 {
		t.Fatalf("verification candidates = %#v, want test and build only", discovery.VerificationCandidates)
	}
	names := []string{discovery.VerificationCandidates[0].Name, discovery.VerificationCandidates[1].Name}
	workspace, err := discovery.BuildWorkspace(Input{Branch: "main", Remote: "origin", VerificationNames: names})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Verification.State != "ready" || len(workspace.Verification.Steps) != 2 {
		t.Fatalf("verification profile = %#v", workspace.Verification)
	}
	for _, step := range workspace.Verification.Steps {
		if len(step.Command) == 0 || step.TimeoutSeconds <= 0 || !step.Required || len(step.SuccessExitCodes) != 1 {
			t.Fatalf("unbounded or implicit verification step = %#v", step)
		}
	}
}

func validVerificationCompose(service string) string {
	return "services:\n  " + service + ":\n" +
		"    image: node:22@sha256:" + strings.Repeat("1", 64) + "\n" +
		"    user: \"65532:65532\"\n    read_only: true\n    cap_drop: [\"ALL\"]\n" +
		"    security_opt: [\"no-new-privileges:true\"]\n    cpus: \"1\"\n" +
		"    mem_limit: 1g\n    pids_limit: 128\n    networks: [verify]\n" +
		"networks:\n  verify:\n    internal: true\n"
}

func nodeProject(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, project, "package.json", "{}\n")
	writeProjectFile(t, project, "package-lock.json", "{}\n")
	writeProjectFile(t, project, "compose.yml", "services:\n  test: {}\n")
	return project
}

func writeProjectFile(t *testing.T, project, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
