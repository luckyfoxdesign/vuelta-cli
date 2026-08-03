package ecosystems

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func writeNPMFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNPMProjectShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		files    map[string]string
		detected bool
		lock     string
		wantErr  string
	}{
		{
			name: "manifest only", detected: true,
			files: map[string]string{npmManifest: `{"name":"demo"}`},
		},
		{
			name: "package lock", detected: true, lock: npmPackageLock,
			files: map[string]string{
				npmManifest: `{"name":"demo"}`, npmPackageLock: `{"lockfileVersion":3}`,
			},
		},
		{
			name: "shrinkwrap", detected: true, lock: npmShrinkwrapLock,
			files: map[string]string{
				npmManifest: `{"name":"demo"}`, npmShrinkwrapLock: `{"lockfileVersion":3}`,
			},
		},
		{
			name: "ambiguous npm locks", wantErr: "both package-lock.json and npm-shrinkwrap.json",
			files: map[string]string{
				npmManifest: `{"name":"demo"}`, npmPackageLock: `{"lockfileVersion":3}`,
				npmShrinkwrapLock: `{"lockfileVersion":3}`,
			},
		},
		{
			name: "pnpm marker is not npm",
			files: map[string]string{
				npmManifest: `{"name":"demo"}`, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
			},
		},
		{
			name:  "declared pnpm is not npm",
			files: map[string]string{npmManifest: `{"packageManager":"pnpm@9.15.0"}`},
		},
		{
			name: "malformed manifest", wantErr: "parse package.json",
			files: map[string]string{npmManifest: `{`},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for name, contents := range testCase.files {
				writeNPMFixture(t, root, name, contents)
			}
			project, err := inspectNPMProject(root)
			if testCase.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("inspectNPMProject() error = %v, want %q", err, testCase.wantErr)
				}
				return
			}
			if err != nil || project.detected != testCase.detected || project.lockFile != testCase.lock {
				t.Fatalf("inspectNPMProject() = %#v, %v", project, err)
			}
		})
	}
}

func TestNPMRootContractsAndMutationUseShrinkwrap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeNPMFixture(t, root, npmManifest, `{"name":"demo"}`)
	writeNPMFixture(t, root, npmShrinkwrapLock, `{"lockfileVersion":3}`)
	adapter := NPM()
	resolver := adapter.(ecosystem.RootInputProvider)
	contract, err := resolver.PackageInputForRoot(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contract.Files) != 2 || contract.Files[1].Path != npmShrinkwrapLock {
		t.Fatalf("contract = %#v", contract)
	}
	mutation, err := adapter.(ecosystem.MutationProvider).Mutation(ecosystem.MutationRequest{
		Root: root, ProfileScanner: "ncu", InstalledTool: true,
	})
	if err != nil || mutation.LockFile != npmShrinkwrapLock {
		t.Fatalf("mutation = %#v, %v", mutation, err)
	}
}

func TestNPMManifestOnlyRejectsEveryMutationContract(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeNPMFixture(t, root, npmManifest, `{"name":"demo"}`)
	adapter := NPM()
	if _, err := adapter.(ecosystem.MutationProvider).Mutation(ecosystem.MutationRequest{
		Root: root, ProfileScanner: "ncu", InstalledTool: true,
	}); err == nil || !strings.Contains(err.Error(), "requires exactly one supported lockfile") {
		t.Fatalf("Mutation() error = %v", err)
	}
	if _, err := adapter.(ecosystem.PlannedMutationProvider).PlannedMutation(ecosystem.PlannedMutationRequest{
		Root: root, ProfileScanner: "ncu", InstalledTool: true,
	}); err == nil || !strings.Contains(err.Error(), "requires exactly one supported lockfile") {
		t.Fatalf("PlannedMutation() error = %v", err)
	}
}

func TestNPMDecoderDropsNormalizedNoOpsAndPreservesRealCandidates(t *testing.T) {
	t.Parallel()
	inputs := map[string][]byte{
		npmManifest: []byte(`{"name":"demo"}`),
		npmPackageLock: []byte(`{
			"lockfileVersion": 3,
			"packages": {
				"node_modules/canvg": {"version":"4.0.3"},
				"node_modules/normalized": {"version":"v3.0.0"},
				"node_modules/real": {"version":"1.0.0"}
			}
		}`),
	}
	report, err := NPM().(ecosystem.CandidateDecoder).DecodeCandidates(
		[]byte(`{"canvg":"4.0.3","normalized":"3.0.0","real":"v2.0.0"}`),
		inputs,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("candidates = %#v, want only the real update", report.Candidates)
	}
	candidate := report.Candidates[0]
	if candidate.Name != "real" || candidate.Current != "1.0.0" || candidate.Target != "2.0.0" {
		t.Fatalf("real candidate = %#v", candidate)
	}
}
