package configinit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
)

func fakeDigestResolver(t *testing.T) func(context.Context, string) (string, error) {
	t.Helper()
	return func(_ context.Context, ref string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
}

func npmVerifyProject(t *testing.T, engines string, scripts string) string {
	t.Helper()
	project := t.TempDir()
	enginesField := ""
	if engines != "" {
		enginesField = `,"engines":{"node":"` + engines + `"}`
	}
	writeProjectFile(t, project, "package.json", `{"scripts":`+scripts+enginesField+`}`)
	writeProjectFile(t, project, "package-lock.json", `{"lockfileVersion":3}`)
	return project
}

// These two cases reproduce the real dev/donutsvg and dev/iholpro package.json
// contents referenced by this task's Context section: donutsvg declares
// engines.node "24.x" and its hand-written compose.verify.yml pins
// node:24-bookworm-slim; iholpro declares no engines and the documented
// manual step used node:22-bookworm-slim, the ResolveRuntime fallback. Both
// projects' only safe script is "build" (dev/preview/start are unsafe).
func TestGenerateVerifyComposeMatchesDonutsvg(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "package.json", `{"scripts":{"dev":"vite","build":"vite build","preview":"vite preview"},"engines":{"node":"24.x"}}`)
	writeProjectFile(t, project, "package-lock.json", `{"lockfileVersion":3}`)
	data, script, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("GenerateVerifyCompose: %v", err)
	}
	if script != "build" {
		t.Fatalf("script = %q, want build", script)
	}
	if !strings.Contains(string(data), "image: node:24-bookworm-slim@sha256:") {
		t.Fatalf("expected node:24-bookworm-slim image, got:\n%s", data)
	}
	if !strings.Contains(string(data), "- npm\n") || !strings.Contains(string(data), "- run\n") || !strings.Contains(string(data), "- build\n") {
		t.Fatalf("expected npm run build command, got:\n%s", data)
	}
	if err := validateGeneratedCompose(project, data); err != nil {
		t.Fatalf("generated compose failed policy validation: %v", err)
	}
}

func TestGenerateVerifyComposeMatchesIholpro(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "package.json", `{"scripts":{"build":"rollup -c","dev":"rollup -c -w","start":"sirv public --no-clear"}}`)
	writeProjectFile(t, project, "package-lock.json", `{"lockfileVersion":2}`)
	data, script, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("GenerateVerifyCompose: %v", err)
	}
	if script != "build" {
		t.Fatalf("script = %q, want build", script)
	}
	if !strings.Contains(string(data), "image: node:22-bookworm-slim@sha256:") {
		t.Fatalf("expected default-fallback node:22-bookworm-slim image, got:\n%s", data)
	}
	if err := validateGeneratedCompose(project, data); err != nil {
		t.Fatalf("generated compose failed policy validation: %v", err)
	}
}

func TestGenerateVerifyComposeUsesDeclaredEnginesNode(t *testing.T) {
	project := npmVerifyProject(t, "24.x", `{"build":"tsc"}`)
	data, script, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("GenerateVerifyCompose: %v", err)
	}
	if script != "build" {
		t.Fatalf("script = %q, want build", script)
	}
	if !strings.Contains(string(data), "image: node:24-bookworm-slim@sha256:") {
		t.Fatalf("expected runtime 24 image, got:\n%s", data)
	}
	if err := validateGeneratedCompose(project, data); err != nil {
		t.Fatalf("generated compose failed policy validation: %v", err)
	}
}

func TestGenerateVerifyComposeFallsBackToDefaultRuntime(t *testing.T) {
	project := npmVerifyProject(t, "", `{"test":"node --test"}`)
	data, script, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("GenerateVerifyCompose: %v", err)
	}
	if script != "test" {
		t.Fatalf("script = %q, want test", script)
	}
	if !strings.Contains(string(data), "image: node:22-bookworm-slim@sha256:") {
		t.Fatalf("expected default runtime 22 image, got:\n%s", data)
	}
}

func TestGenerateVerifyComposePNPM(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "package.json", `{"scripts":{"build":"tsc"}}`)
	writeProjectFile(t, project, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	data, script, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("GenerateVerifyCompose: %v", err)
	}
	if script != "build" {
		t.Fatalf("script = %q, want build", script)
	}
	if !strings.Contains(string(data), "npm_config_cache: /tmp/pnpm") {
		t.Fatalf("expected pnpm cache environment, got:\n%s", data)
	}
	if !strings.Contains(string(data), "- pnpm\n") {
		t.Fatalf("expected pnpm command, got:\n%s", data)
	}
	if err := validateGeneratedCompose(project, data); err != nil {
		t.Fatalf("generated compose failed policy validation: %v", err)
	}
}

func TestGenerateVerifyComposeMultipleSafeScriptsFailClosed(t *testing.T) {
	project := npmVerifyProject(t, "", `{"test":"node --test","build":"tsc"}`)
	_, _, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	var missing *MissingValueError
	if !errors.As(err, &missing) {
		t.Fatalf("expected MissingValueError, got %v", err)
	}
	if missing.Flag != "--script" {
		t.Fatalf("flag = %q, want --script", missing.Flag)
	}
	if len(missing.Options) != 2 || missing.Options[0] != "test" || missing.Options[1] != "build" {
		t.Fatalf("options = %v, want [test build]", missing.Options)
	}
}

func TestGenerateVerifyComposeOnlyUnsafeScriptsFailClosed(t *testing.T) {
	project := npmVerifyProject(t, "", `{"dev":"vite","serve":"vite preview","start":"node server.js"}`)
	_, _, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err == nil || !strings.Contains(err.Error(), "--script NAME") {
		t.Fatalf("expected fail-closed error suggesting --script NAME, got %v", err)
	}
}

func TestGenerateVerifyComposeExplicitScriptOverride(t *testing.T) {
	project := npmVerifyProject(t, "", `{"test":"node --test","build":"tsc","custom:release":"tsc -p tsconfig.release.json"}`)
	_, script, err := GenerateVerifyCompose(context.Background(), project, "custom:release", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("GenerateVerifyCompose: %v", err)
	}
	if script != "custom:release" {
		t.Fatalf("script = %q, want custom:release", script)
	}
}

func TestGenerateVerifyComposeRejectsUnsafeExplicitScript(t *testing.T) {
	project := npmVerifyProject(t, "", `{"build":"tsc","watch":"tsc --watch"}`)
	_, _, err := GenerateVerifyCompose(context.Background(), project, "watch", fakeDigestResolver(t))
	if err == nil || !strings.Contains(err.Error(), "not a safe verification script") {
		t.Fatalf("expected unsafe script rejection, got %v", err)
	}
}

func TestGenerateVerifyComposeFailsClosedForUnsupportedStack(t *testing.T) {
	project := t.TempDir()
	writeProjectFile(t, project, "pyproject.toml", "[tool.poetry]\nname = \"x\"\n")
	writeProjectFile(t, project, "poetry.lock", "")
	_, _, err := GenerateVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err == nil || !strings.Contains(err.Error(), "no verify template exists yet") {
		t.Fatalf("expected fail-closed unsupported-stack error, got %v", err)
	}
}

func TestWriteVerifyComposeDigestFailureLeavesNoFile(t *testing.T) {
	project := npmVerifyProject(t, "", `{"build":"tsc"}`)
	failing := func(context.Context, string) (string, error) { return "", errors.New("registry unreachable") }
	_, _, err := WriteVerifyCompose(context.Background(), project, "", failing)
	if err == nil || !strings.Contains(err.Error(), "registry unreachable") {
		t.Fatalf("expected digest resolution error, got %v", err)
	}
	entries, readErr := os.ReadDir(project)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if entry.Name() == "compose.verify.yml" {
			t.Fatal("compose.verify.yml must not exist after digest resolution failure")
		}
	}
}

func TestWriteVerifyComposeNeverOverwrites(t *testing.T) {
	project := npmVerifyProject(t, "", `{"build":"tsc"}`)
	existing := filepath.Join(project, "compose.verify.yml")
	if err := os.WriteFile(existing, []byte("hand-written"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := WriteVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already-exists error, got %v", err)
	}
	data, readErr := os.ReadFile(existing)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "hand-written" {
		t.Fatal("existing compose.verify.yml must be left untouched")
	}
}

func TestWriteVerifyComposeRoundTripsThroughValidator(t *testing.T) {
	project := npmVerifyProject(t, "24", `{"build":"tsc"}`)
	path, script, err := WriteVerifyCompose(context.Background(), project, "", fakeDigestResolver(t))
	if err != nil {
		t.Fatalf("WriteVerifyCompose: %v", err)
	}
	if script != "build" {
		t.Fatalf("script = %q, want build", script)
	}
	if filepath.Base(path) != "compose.verify.yml" {
		t.Fatalf("path = %q, want compose.verify.yml", path)
	}
	if err := testrunner.ValidateComposeService(project, "compose.verify.yml", "verify"); err != nil {
		t.Fatalf("round-trip validation failed: %v", err)
	}
	entries, readErr := os.ReadDir(project)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "compose.verify.yml" && !strings.HasPrefix(name, ".") && name != "package.json" && name != "package-lock.json" {
			t.Fatalf("unexpected leftover file %q", name)
		}
		if strings.HasPrefix(name, ".compose.verify.yml.check-") {
			t.Fatalf("validation temp file %q was not cleaned up", name)
		}
	}
}
