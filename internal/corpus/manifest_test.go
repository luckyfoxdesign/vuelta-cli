package corpus

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManifestStrictAndSafe(t *testing.T) {
	t.Parallel()
	const valid = `
schema_version: 1
cases:
  - name: example-npm
    url: https://github.com/example/project
    commit: 0123456789012345678901234567890123456789
    subdir: ""
    expected_stack: node
    expected_package_manager: npm
    expected_lock_format: npm-v3
    license: MIT
    features: [single-package]
    scenarios:
      - name: default
        args: []
`
	manifest, err := ParseManifest([]byte(valid), false)
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if got := manifest.Cases[0].Scenarios[0].EffectiveRepeat(); got != 2 {
		t.Fatalf("EffectiveRepeat() = %d, want 2", got)
	}

	tests := map[string]string{
		"unknown":       strings.Replace(valid, "schema_version: 1", "schema_version: 1\nunknown: true", 1),
		"credentials":   strings.Replace(valid, "https://github.com/example/project", "https://user@github.com/example/project", 1),
		"query":         strings.Replace(valid, "https://github.com/example/project", "https://github.com/example/project?x=1", 1),
		"short commit":  strings.Replace(valid, "0123456789012345678901234567890123456789", "0123456", 1),
		"unsafe name":   strings.Replace(valid, "example-npm", "../escape", 1),
		"unsafe subdir": strings.Replace(valid, `subdir: ""`, "subdir: ../../escape", 1),
		"unsafe arg":    strings.Replace(valid, "args: []", "args: [--directory, /tmp]", 1),
		"anchor":        strings.Replace(valid, "features: [single-package]", "features: &features [single-package]", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseManifest([]byte(input), false); err == nil {
				t.Fatal("ParseManifest() accepted unsafe input")
			}
		})
	}
}

func TestExpectationRequiresCompletePartialContract(t *testing.T) {
	t.Parallel()
	expectation := Expectation{
		AllowPartial: true, AllowedExits: []int{6}, AllowedStatuses: []string{"partial"},
	}
	if err := expectation.validate(); err == nil {
		t.Fatal("partial expectation without capability contract was accepted")
	}
	expectation.Capabilities = []ExpectedCapability{{
		Name: "package_updates", Status: "unavailable", ReasonCode: "toolchain_incompatible",
	}}
	expectation.FailedStages = []ExpectedFailure{{
		Stage: "candidate", ReasonCode: "toolchain_incompatible",
	}}
	if err := expectation.validate(); err != nil {
		t.Fatalf("valid capability expectation rejected: %v", err)
	}
	expectation.AllowedStatuses = []string{"scan-only"}
	if err := expectation.validate(); err == nil {
		t.Fatal("hyphenated scan-only status was accepted")
	}
}

func TestValidateStableCoverage(t *testing.T) {
	t.Parallel()
	managers := []string{
		"npm", "npm", "npm", "pnpm", "pnpm", "pnpm",
		"poetry", "poetry", "poetry", "uv", "uv", "uv",
		"pip-tools", "pip-tools", "pip-tools",
		"requirements", "requirements", "requirements", "bun", "bun",
	}
	requiredFeatures := []string{
		"monorepo-or-workspaces", "nested-root", "dockerfile",
		"lockfile-schema-variation", "dev-or-optional-dependencies",
		"prerelease-or-nonstandard-constraints",
		"requirements-include-directive", "requirements-constraint-directive",
		"requirements-hashes", "requirements-url-dependency",
		"manifest-without-lockfile", "large-project",
		"multi-stack-node", "multi-stack-python",
	}
	manifest := Manifest{SchemaVersion: 1}
	for i, manager := range managers {
		stack := "python"
		if manager == "npm" || manager == "pnpm" || manager == "bun" {
			stack = "node"
		}
		features := []string{"single-package"}
		if i < len(requiredFeatures) {
			features = append(features, requiredFeatures[i])
		}
		scenario := Scenario{Name: "default"}
		if manager == "bun" {
			features = append(features, "bun-capability")
			scenario.Expect = Expectation{
				AllowedStatuses: []string{"partial"},
				AllowedExits:    []int{6},
				AllowPartial:    true,
				Capabilities: []ExpectedCapability{{
					Name: "package_updates", Status: "unavailable", ReasonCode: "toolchain_incompatible",
				}},
				FailedStages: []ExpectedFailure{{
					Stage: "candidate", ReasonCode: "toolchain_incompatible",
				}},
			}
		}
		manifest.Cases = append(manifest.Cases, Case{
			Name: "case-" + string(rune('a'+i)), URL: "https://github.com/example/repo" + string(rune('a'+i)),
			Commit: strings.Repeat("a", 40), ExpectedStack: stack,
			ExpectedPackageManager: manager, ExpectedLockFormat: "format",
			License: "MIT", Features: features,
			Scenarios: []Scenario{scenario},
		})
	}
	if err := manifest.Validate(false); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := manifest.ValidateStableCoverage(); err != nil {
		t.Fatalf("ValidateStableCoverage() error = %v", err)
	}
}

func TestStableExampleManifest(t *testing.T) {
	t.Parallel()
	manifest, err := LoadManifest(filepath.Join("..", "..", "acceptance", "corpus.example.yaml"), false)
	if err != nil {
		t.Fatalf("LoadManifest() error = %v", err)
	}
	if err := manifest.ValidateStableCoverage(); err != nil {
		t.Fatalf("ValidateStableCoverage() error = %v", err)
	}
}
