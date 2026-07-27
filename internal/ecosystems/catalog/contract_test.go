package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestBuiltInAdapterContracts(t *testing.T) {
	t.Parallel()
	type adapterCase struct {
		key       string
		files     map[string]string
		output    string
		mutable   bool
		scannable bool
	}
	cases := []adapterCase{
		{key: "node/npm", mutable: true, scannable: true, files: map[string]string{
			"package.json":      `{"engines":{"node":"22.x"},"packageManager":"npm@10.9.2"}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.0"}}}`,
		}, output: `{"demo":"2.0.0"}`},
		{key: "node/pnpm", mutable: true, scannable: true, files: map[string]string{
			"package.json":   `{"engines":{"node":"22.x"},"packageManager":"pnpm@9.15.0"}`,
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
		}, output: `{"demo":{"current":"1.0.0","latest":"2.0.0"}}`},
		{key: "node/bun", files: map[string]string{
			"package.json": `{"engines":{"node":"22.x"},"packageManager":"bun@1.2.0"}`,
			"bun.lock":     "[lockfile]\n",
		}},
		{key: "python/poetry", mutable: true, scannable: true, files: map[string]string{
			"pyproject.toml": "[project]\nrequires-python = \">=3.12,<3.13\"\n",
			"poetry.lock":    "package = []\n",
		}, output: `[{"name":"demo","version":"1.0.0","latest":"2.0.0"}]`},
		{key: "python/uv", mutable: true, scannable: true, files: map[string]string{
			"pyproject.toml": "[project]\nrequires-python = \">=3.12,<3.13\"\n",
			"uv.lock":        "version = 1\n",
		}, output: `{"resolution":{"demo==1.0.0":{"name":"demo","version":"1.0.0","latest_version":"2.0.0"}}}`},
		{key: "python/pip-tools", mutable: true, scannable: true, files: map[string]string{
			"pyproject.toml":   "[project]\nrequires-python = \">=3.12,<3.13\"\n",
			"requirements.in":  "demo==1.0.0\n",
			"requirements.txt": "demo==1.0.0\n",
		}, output: `{"candidates":[{"name":"demo","current":"1.0.0","latest_version":"2.0.0"}],"diagnostics":[]}`},
		{key: "python/requirements", scannable: true, files: map[string]string{
			"requirements.txt": "demo==1.0.0\n",
		}, output: `{"candidates":[{"name":"demo","current":"1.0.0","latest_version":"2.0.0"}],"diagnostics":[]}`},
	}

	registry, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Adapters()) != len(cases) {
		t.Fatalf("catalog has %d adapters, want %d", len(registry.Adapters()), len(cases))
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.key, func(t *testing.T) {
			t.Parallel()
			stack, manager := splitKey(t, testCase.key)
			adapter, err := registry.Lookup(stack, manager)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			for name, contents := range testCase.files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			detector := adapter.(ecosystem.Detector)
			if detected, err := detector.Detect(root); err != nil || !detected {
				t.Fatalf("Detect() = %t, %v", detected, err)
			}
			inputs := adapter.(ecosystem.InputProvider).PackageInput(false)
			if len(inputs.Files) == 0 {
				t.Fatal("candidate input contract is empty")
			}
			constraints, err := adapter.(ecosystem.ConstraintDetector).DetectConstraints(root, "linux/amd64")
			if err != nil || constraints.Key != adapter.Key() || constraints.LockFormat == "" {
				t.Fatalf("constraints = %#v, %v", constraints, err)
			}
			if len(adapter.(ecosystem.ChangePolicy).AllowedChangedPaths()) == 0 {
				t.Fatal("changed-path policy is empty")
			}

			_, hasScanner := adapter.(ecosystem.ScannerProvider)
			if hasScanner != testCase.scannable {
				t.Fatalf("scanner capability = %t, want %t", hasScanner, testCase.scannable)
			}
			_, hasMutation := adapter.(ecosystem.MutationProvider)
			_, hasPlannedMutation := adapter.(ecosystem.PlannedMutationProvider)
			if hasMutation != testCase.mutable || hasPlannedMutation != testCase.mutable {
				t.Fatalf("mutation capabilities = %t/%t, want %t", hasMutation, hasPlannedMutation, testCase.mutable)
			}
			if !testCase.scannable {
				return
			}
			policy := adapter.(ecosystem.ProfilePolicyProvider).ProfilePolicy()
			spec, err := adapter.(ecosystem.ScannerProvider).Scanner(ecosystem.ScannerRequest{
				ProfileScanner: policy.ExpectedScanner, InstalledTool: true,
			})
			if err != nil || len(spec.Args) == 0 {
				t.Fatalf("scanner spec = %#v, %v", spec, err)
			}
			inputData := make(map[string][]byte)
			for name, contents := range testCase.files {
				inputData[name] = []byte(contents)
			}
			report, err := adapter.(ecosystem.CandidateDecoder).DecodeCandidates([]byte(testCase.output), inputData)
			if err != nil || len(report.Candidates) != 1 || report.Candidates[0].Target != "2.0.0" {
				t.Fatalf("decoded report = %#v, %v", report, err)
			}
			if toolchain, ok := adapter.(ecosystem.ToolchainProvider); ok {
				resolved, err := toolchain.DefaultToolchain(constraints)
				if err != nil || resolved.Key != adapter.Key() || resolved.AdapterVersion != adapter.Metadata().Version {
					t.Fatalf("default toolchain = %#v, %v", resolved, err)
				}
			}
		})
	}
}

func splitKey(t *testing.T, key string) (string, string) {
	t.Helper()
	for index := range key {
		if key[index] == '/' {
			return key[:index], key[index+1:]
		}
	}
	t.Fatalf("invalid test key %q", key)
	return "", ""
}
