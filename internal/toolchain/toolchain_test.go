package toolchain

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

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
	if got.ID != "node24-npm" || identity.ProfileID != got.ID || identity.Hash == "" || constraints.LockFormat != "npm-v3" {
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

func TestResolvePNPMBunAndPythonProfiles(t *testing.T) {
	tests := []struct {
		name, stack, manager, runtime, managerVersion, lock, manifestName, manifest, lockName, lockContents string
	}{
		{"pnpm", "node", "pnpm", "22", "9.15.0", "pnpm-v9", "package.json", `{"engines":{"node":"22.x"},"packageManager":"pnpm@9.15.0"}`, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n"},
		{"bun", "node", "bun", "22", "1.2.0", "bun-text", "package.json", `{"engines":{"node":"22.x"},"packageManager":"bun@1.2.0"}`, "bun.lock", "[lockfile]\n"},
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
			selected.Scanner = map[string]string{"pnpm": "pnpm", "bun": "ncu", "poetry": "poetry", "uv": "uv", "pip-tools": "pip"}[testCase.manager]
			selected.ScannerVersion = testCase.managerVersion
			ws := config.Workspace{Path: root, Stack: testCase.stack, PackageManager: testCase.manager, Platform: "linux/amd64"}
			got, _, _, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: []config.ToolchainProfile{selected}}})
			if err != nil || got.ID != selected.ID {
				t.Fatalf("Resolve() = %q, %v", got.ID, err)
			}
		})
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
	if _, _, _, err := Resolve(ws, config.Config{Update: config.UpdateConfig{ToolchainProfiles: profiles}}); err == nil || !strings.Contains(err.Error(), "no compatible") {
		t.Fatalf("unsupported resolution error = %v", err)
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
