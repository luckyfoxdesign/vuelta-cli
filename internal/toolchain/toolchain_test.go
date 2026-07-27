package toolchain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestSelectRealWorldRuntimeConstraints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		stack          string
		manager        string
		manifestName   string
		manifest       string
		lockName       string
		lock           string
		wantRuntime    string
		wantConstraint string
	}{
		{
			name: "Node exact patch", stack: config.StackNode, manager: "npm",
			manifestName: "package.json",
			manifest:     `{"engines":{"node":"24.7.0"},"packageManager":"npm@11.4.2"}`,
			lockName:     "package-lock.json", lock: `{"lockfileVersion":3}`,
			wantRuntime: "24", wantConstraint: "=24.7.0",
		},
		{
			name: "Node open lower bound", stack: config.StackNode, manager: "npm",
			manifestName: "package.json",
			manifest:     `{"engines":{"node":">=18.0.0"},"packageManager":"npm@11.4.2"}`,
			lockName:     "package-lock.json", lock: `{"lockfileVersion":3}`,
			wantRuntime: "24", wantConstraint: ">=18.0.0",
		},
		{
			name: "Poetry caret", stack: config.StackPython, manager: "poetry",
			manifestName: "pyproject.toml",
			manifest:     "[tool.poetry.dependencies]\npython = \"^3.9\"\n",
			lockName:     "poetry.lock", lock: "package = []\n",
			wantRuntime: "3.13", wantConstraint: ">=3.9.0 <4.0.0",
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			write(t, root, testCase.manifestName, testCase.manifest)
			write(t, root, testCase.lockName, testCase.lock)
			selection, err := Select(config.Workspace{
				Path: root, Stack: testCase.stack,
				PackageManager: testCase.manager, Platform: "linux/amd64",
			}, config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if selection.Profile.Runtime != testCase.wantRuntime ||
				selection.RuntimeConstraint != testCase.wantConstraint ||
				selection.Source != SourceDefault {
				t.Fatalf("Select() = %#v", selection)
			}
		})
	}
}

func TestSelectCompatibleOperatorOverrideRetainsPrecedence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":">=18.0.0"},"packageManager":"npm@10.9.2"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	override := profile("approved-node20", "npm", "20", "10.9.2", "npm-v3")
	selection, err := Select(config.Workspace{
		Path: root, Stack: config.StackNode, PackageManager: "npm",
		Platform: "linux/amd64", ToolchainProfile: override.ID,
	}, config.Config{Update: config.UpdateConfig{ToolchainProfiles: []config.ToolchainProfile{override}}})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Source != SourceOverride || selection.Profile.ID != override.ID ||
		selection.Profile.Runtime != "20" || selection.RuntimeConstraint != ">=18.0.0" {
		t.Fatalf("Select() = %#v", selection)
	}
}

func TestSelectReturnsTypedRuntimeConstraintFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, constraint, wantCode string
	}{
		{"unsupported union", ">=20 || >=24", ecosystem.RuntimeConstraintUnsupportedSyntax},
		{"no compatible runtime", "25.0.0", ecosystem.RuntimeConstraintNoCompatible},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "package.json", fmt.Sprintf(`{"engines":{"node":%q}}`, testCase.constraint))
			write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
			_, err := Select(config.Workspace{
				Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64",
			}, config.Config{})
			var constraintErr *ecosystem.RuntimeConstraintError
			if !errors.As(err, &constraintErr) || constraintErr.ReasonCode != testCase.wantCode {
				t.Fatalf("Select() error = %T %v", err, err)
			}
		})
	}
}

func TestResolveNodeRuntimeLockAndManagerVersion(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"24.x"},"packageManager":"npm@11.4.2"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	profiles := []config.ToolchainProfile{
		profile("node22-npm", "npm", "22", "11.4.2", "npm-v3"),
		profile("node24-npm", "npm", "24", "11.4.2", "npm-v3"),
	}
	ws := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	got, identity, constraints, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: profiles}})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "node24-npm" || identity.ProfileID != got.ID || identity.Source != SourceOverride || identity.Hash == "" || constraints.LockFormat != "npm-v3" {
		t.Fatalf("resolution = %#v, %#v, %#v", got, identity, constraints)
	}
}

func TestResolveNodeRuntimeAndNPMLockMatrix(t *testing.T) {
	for _, testCase := range []struct {
		major int
		lock  int
	}{
		{20, 2}, {20, 3}, {22, 2}, {22, 3}, {24, 2}, {24, 3},
	} {
		t.Run(fmt.Sprintf("node%d-lock%d", testCase.major, testCase.lock), func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "package.json", fmt.Sprintf(`{"engines":{"node":"%d.x"},"packageManager":"npm@10.9.2"}`, testCase.major))
			write(t, root, "package-lock.json", fmt.Sprintf(`{"lockfileVersion":%d}`, testCase.lock))
			selected := profile(fmt.Sprintf("node%d-npm", testCase.major), "npm", strconv.Itoa(testCase.major), "10.9.2", fmt.Sprintf("npm-v%d", testCase.lock))
			ws := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
			got, _, _, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: []config.ToolchainProfile{selected}}})
			if err != nil || got.ID != selected.ID {
				t.Fatalf("Resolve() = %q, %v", got.ID, err)
			}
		})
	}
}

func TestResolvePNPMAndPythonProfiles(t *testing.T) {
	tests := []struct {
		name, stack, manager, runtime, managerVersion, lock, manifestName, manifest, lockName, lockContents string
	}{
		{"pnpm", "node", "pnpm", "22", "9.15.0", "pnpm-v9", "package.json", `{"engines":{"node":"22.x"},"packageManager":"pnpm@9.15.0"}`, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n"},
		{"poetry", "python", "poetry", "3.12", "2.1.1", "poetry-v2", "pyproject.toml", "[project]\nrequires-python = \">=3.12,<3.13\"\n", "poetry.lock", "package = []\n"},
		{"uv", "python", "uv", "3.12", "0.6.14", "uv-v1", "pyproject.toml", "[project]\nrequires-python = \">=3.12,<3.13\"\n", "uv.lock", "version = 1\n"},
		{"pip-tools", "python", "pip-tools", "3.12", "7.5.0", "requirements", "pyproject.toml", "[project]\nrequires-python = \">=3.12,<3.13\"\n", "requirements.txt", "example==1.0.0\n"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, testCase.manifestName, testCase.manifest)
			write(t, root, testCase.lockName, testCase.lockContents)
			selected := profile(testCase.name, testCase.manager, testCase.runtime, testCase.managerVersion, testCase.lock)
			selected.Stack = testCase.stack
			selected.Scanner = map[string]string{"pnpm": "pnpm", "poetry": "poetry", "uv": "uv", "pip-tools": "vuelta-pip-tools-scan"}[testCase.manager]
			selected.ScannerVersion = testCase.managerVersion
			ws := config.Workspace{Path: root, Stack: testCase.stack, PackageManager: testCase.manager, Platform: "linux/amd64"}
			got, _, _, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: []config.ToolchainProfile{selected}}})
			if err != nil || got.ID != selected.ID {
				t.Fatalf("Resolve() = %q, %v", got.ID, err)
			}
		})
	}
}

func TestResolveRejectsBunWithActionableDiagnostic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"22.x"},"packageManager":"bun@1.2.0"}`)
	write(t, root, "bun.lock", "[lockfile]\n")
	selected := profile("bun", "bun", "22", "1.2.0", "bun-text")
	ws := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "bun", Platform: "linux/amd64"}
	_, _, constraints, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: []config.ToolchainProfile{selected}}})
	if err == nil || !strings.Contains(err.Error(), "npm-check-updates") || !strings.Contains(err.Error(), "use npm or pnpm") {
		t.Fatalf("bun resolution error = %v", err)
	}
	if constraints.PackageManager != "bun" || constraints.LockFormat != "bun-text" {
		t.Fatalf("bun constraints = %#v", constraints)
	}
}

func TestResolveRejectsUnsupportedAndAmbiguousConstraints(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	profiles := []config.ToolchainProfile{
		profile("node20-npm", "npm", "20", "10.9.2", "npm-v3"),
		profile("node22-npm", "npm", "22", "10.9.2", "npm-v3"),
	}
	ws := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	if _, _, _, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: profiles}}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous resolution error = %v", err)
	}
	write(t, root, "package.json", `{"engines":{"node":"24.x"}}`)
	selection, err := Select(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: profiles}})
	if err != nil || selection.Source != SourceDefault || selection.Profile.Runtime != "24" {
		t.Fatalf("default fallback = %#v, %v", selection, err)
	}
}

func TestSelectEmbeddedDefaultMatrixWithoutConfigProfiles(t *testing.T) {
	for _, runtimeVersion := range []string{"20", "22", "24"} {
		for _, manager := range []string{"npm", "pnpm"} {
			t.Run("node"+runtimeVersion+"-"+manager, func(t *testing.T) {
				root := t.TempDir()
				managerVersion := "10.9.2"
				if manager == "pnpm" {
					managerVersion = "9.15.0"
					write(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
				} else {
					write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
				}
				write(t, root, "package.json", fmt.Sprintf(`{"engines":{"node":"%s.x"},"packageManager":"%s@%s"}`, runtimeVersion, manager, managerVersion))
				selection, err := Select(config.Workspace{Path: root, Stack: config.StackNode, PackageManager: manager, Platform: "linux/amd64"}, config.Config{})
				if err != nil || selection.Source != SourceDefault || selection.Profile.Runtime != runtimeVersion || selection.Profile.PackageManagerVersion != managerVersion || selection.build == nil {
					t.Fatalf("Select() = %#v, %v", selection, err)
				}
			})
		}
	}

	for _, runtimeVersion := range []string{"3.11", "3.12", "3.13"} {
		for _, manager := range []string{"poetry", "uv"} {
			t.Run("python"+runtimeVersion+"-"+manager, func(t *testing.T) {
				root := t.TempDir()
				write(t, root, "pyproject.toml", fmt.Sprintf("[project]\nrequires-python = \"%s\"\n", runtimeVersion))
				lock := map[string]string{"poetry": "poetry.lock", "uv": "uv.lock"}[manager]
				write(t, root, lock, "version = 1\n")
				selection, err := Select(config.Workspace{Path: root, Stack: config.StackPython, PackageManager: manager, Platform: "linux/arm64"}, config.Config{})
				if err != nil || selection.Profile.Runtime != runtimeVersion || selection.Source != SourceDefault {
					t.Fatalf("Select() = %#v, %v", selection, err)
				}
			})
		}
	}
}

func TestDetectRejectsManagerConflictAndMalformedLock(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"packageManager":"pnpm@10.0.0"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	ws := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/arm64"}
	if _, err := Detect(ws); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("manager conflict error = %v", err)
	}
	write(t, root, "package.json", `{}`)
	write(t, root, "package-lock.json", `{}`)
	if _, err := Detect(ws); err == nil || !strings.Contains(err.Error(), "lockfileVersion") {
		t.Fatalf("lock error = %v", err)
	}
}

func TestSelectRequirementsOnlyEmbeddedScanner(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "requests==2.31.0\n")
	selection, err := Select(config.Workspace{Path: root, Stack: config.StackPython, PackageManager: "requirements", Platform: "linux/amd64"}, config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Source != SourceDefault || selection.Profile.PackageManager != "requirements" || selection.Profile.Scanner != "vuelta-pip-tools-scan" || selection.Profile.LockFormats[0] != "requirements-direct" || selection.build == nil || selection.build.Dockerfile != "python-pip-tools.Dockerfile" {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestSelectPipToolsDefaultsWithoutPyprojectMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, "requirements.in", "requests\n")
	write(t, root, "requirements.txt", "requests==2.31.0\n")
	selection, err := Select(config.Workspace{
		Path: root, Stack: config.StackPython, PackageManager: "pip-tools",
		Platform: "linux/amd64",
	}, config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Source != SourceDefault ||
		selection.Constraints.RuntimeConstraintSource != ecosystem.RuntimeConstraintSourceDefault ||
		selection.RuntimeConstraint != "" ||
		selection.Profile.Runtime != "3.12" ||
		selection.Profile.ID != "default-python312-pip-tools" {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestSelectPipToolsHonorsPresentRuntimeMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, "requirements.in", "requests\n")
	write(t, root, "requirements.txt", "requests==2.31.0\n")
	write(t, root, "pyproject.toml", "[project]\nrequires-python = \">=3.11,<3.12\"\n")
	selection, err := Select(config.Workspace{
		Path: root, Stack: config.StackPython, PackageManager: "pip-tools",
		Platform: "linux/amd64",
	}, config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Constraints.RuntimeConstraintSource != ecosystem.RuntimeConstraintSourceProject ||
		selection.RuntimeConstraint != ">=3.11.0 <3.12.0" ||
		selection.Profile.Runtime != "3.11" {
		t.Fatalf("selection = %#v", selection)
	}
}

func profile(id, manager, runtime, managerVersion, lock string) config.ToolchainProfile {
	return config.ToolchainProfile{
		Version: config.ToolchainProfileVersion, ID: id, Stack: config.StackNode, PackageManager: manager,
		Runtime: runtime, PackageManagerVersion: managerVersion, Scanner: "ncu", ScannerVersion: "18.1.1",
		Image: "registry.example/scanner@sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64", User: "10001:10001",
		LockFormats: []string{lock}, Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: true, ReleaseAge: true},
	}
}

func write(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBindsAdapterAndAcceptsOnlyLegacyUnboundCompatibility(t *testing.T) {
	t.Parallel()
	selected := profile("node22-npm", "npm", "22", "10.9.2", "npm-v3")
	current, err := IdentityForResolvedProfile(selected, SourceOverride, selected.Image)
	if err != nil {
		t.Fatal(err)
	}
	if current.AdapterID != "node/npm" || current.AdapterVersion == "" {
		t.Fatalf("adapter identity = %#v", current)
	}
	legacy, err := identityForResolvedProfile(selected, SourceOverride, selected.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	if !MatchesResolvedIdentity(legacy, selected, current) {
		t.Fatal("legacy short-lived snapshot identity was not accepted")
	}
	tampered := current
	tampered.AdapterVersion = "different"
	if MatchesResolvedIdentity(tampered, selected, current) {
		t.Fatal("changed adapter version was accepted")
	}
}
