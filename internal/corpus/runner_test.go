package corpus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSources struct {
	mu       sync.Mutex
	prepared []string
	cacheHit bool
}

func (f *fakeSources) Prepare(_ context.Context, _ string, tempRoot string, corpusCase Case) (PreparedSource, error) {
	f.mu.Lock()
	f.prepared = append(f.prepared, corpusCase.Name)
	f.mu.Unlock()
	root, err := os.MkdirTemp(tempRoot, corpusCase.Name+"-")
	if err != nil {
		return PreparedSource{}, err
	}
	scanRoot := filepath.Join(root, filepath.FromSlash(corpusCase.Subdir))
	if err := os.MkdirAll(scanRoot, 0o700); err != nil {
		return PreparedSource{}, err
	}
	if err := os.WriteFile(filepath.Join(scanRoot, "package.json"), []byte("{}"), 0o600); err != nil {
		return PreparedSource{}, err
	}
	return PreparedSource{
		Root: root, ScanRoot: scanRoot, BaseCommit: corpusCase.Commit, CacheHit: f.cacheHit,
		Cleanup: func() error { return os.RemoveAll(root) },
	}, nil
}

type fakeScanner struct {
	mu       sync.Mutex
	requests []ScanRequest
	results  []fakeScanResult
}

type fakeScanResult struct {
	output string
	exit   int
	err    error
	mutate func(string) error
}

func (f *fakeScanner) Preflight(context.Context, string) (Environment, error) {
	return Environment{DockerOS: "linux", Architecture: "amd64", Scanner: "fake"}, nil
}

func (f *fakeScanner) Scan(_ context.Context, request ScanRequest) (ProcessObservation, error) {
	f.mu.Lock()
	index := len(f.requests)
	f.requests = append(f.requests, request)
	result := f.results[index]
	f.mu.Unlock()
	if result.mutate != nil {
		if err := result.mutate(request.Directory); err != nil {
			return ProcessObservation{}, err
		}
	}
	return ProcessObservation{
		Stdout: []byte(result.output), ExitCode: result.exit, Duration: time.Millisecond,
	}, result.err
}

const cleanEnvelope = `{"format":1,"command":"scan","config":{"detected_stacks":["node"]},"results":[{"status":"clean","stages":[],"diagnostics":[],"warnings":[],"capabilities":[],"package_updates":{"status":"available"},"toolchain":{"package_manager":"npm","lock_formats":["npm-v3"]}}],"warnings":[],"errors":[]}`

func testCase(name string) Case {
	return Case{
		Name: name, URL: "https://github.com/example/" + name,
		Commit: strings.Repeat("a", 40), ExpectedStack: "node",
		ExpectedPackageManager: "npm", ExpectedLockFormat: "npm-v3",
		License: "MIT", Features: []string{"single-package"},
		Scenarios: []Scenario{{Name: "default", Repeat: 1}},
	}
}

func TestHarnessContinuesAfterTimeoutAndDiscoveryIsNonBlocking(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sources := &fakeSources{}
	scanner := &fakeScanner{results: []fakeScanResult{
		{err: ErrTimeout},
		{output: cleanEnvelope},
		{exit: 4, output: cleanEnvelope},
	}}
	harness := Harness{Sources: sources, Scanner: scanner}
	report, runDir, exit, err := harness.Execute(context.Background(), HarnessInput{
		Root: root, ManifestBytes: []byte("manifest"),
		Stable:    []Case{testCase("timeout-case"), testCase("next-case")},
		Discovery: []Case{testCase("discovery-case")},
		Now:       time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if exit != 1 || report.Summary.StableFailed != 1 || report.Summary.DiscoveryFindings != 1 {
		t.Fatalf("exit/report summary = %d/%#v", exit, report.Summary)
	}
	if len(scanner.requests) != 3 {
		t.Fatalf("scanner requests = %d, want 3", len(scanner.requests))
	}
	if _, err := os.Stat(filepath.Join(runDir, "report.json")); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "cache")); !os.IsNotExist(err) {
		t.Fatal("harness unexpectedly removed or created source cache")
	}
}

func TestHarnessTwoPassAndStackSequenceShareFreshCase(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	corpusCase := testCase("stack-case")
	corpusCase.Scenarios = []Scenario{
		{Name: "onboard", Args: nil, Repeat: 1},
		{Name: "switch", Args: []string{"--stack", "node"}, Repeat: 1},
		{Name: "persist", Args: nil, Repeat: 1},
	}
	scanner := &fakeScanner{results: []fakeScanResult{
		{output: cleanEnvelope, mutate: addOnboarding},
		{output: cleanEnvelope},
		{output: cleanEnvelope},
	}}
	_, _, exit, err := (Harness{Sources: &fakeSources{cacheHit: true}, Scanner: scanner}).Execute(
		context.Background(),
		HarnessInput{Root: root, ManifestBytes: []byte("manifest"), Stable: []Case{corpusCase}, Now: time.Date(2026, 7, 27, 2, 0, 0, 0, time.UTC)},
	)
	if err != nil || exit != 0 {
		t.Fatalf("Execute() = exit %d, err %v", exit, err)
	}
	if len(scanner.requests) != 3 || strings.Join(scanner.requests[1].Args, " ") != "--stack node" {
		t.Fatalf("requests = %#v", scanner.requests)
	}
	if scanner.requests[0].Directory != scanner.requests[2].Directory {
		t.Fatal("scenario sequence did not preserve one fresh case work copy")
	}
}

func TestHarnessRejectsUnexpectedSourceMutation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	scanner := &fakeScanner{results: []fakeScanResult{{
		output: cleanEnvelope,
		mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"changed":true}`), 0o600)
		},
	}}}
	report, _, exit, err := (Harness{Sources: &fakeSources{}, Scanner: scanner}).Execute(
		context.Background(),
		HarnessInput{Root: root, ManifestBytes: []byte("manifest"), Stable: []Case{testCase("mutation-case")}, Now: time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if exit != 1 || report.Results[0].ObservedCategory != "unexpected-filesystem-change" {
		t.Fatalf("exit/result = %d/%#v", exit, report.Results[0])
	}
}

func TestHarnessRequirementsAndBunContractsWithoutNetwork(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	requirements := testCase("requirements-contract")
	requirements.ExpectedStack = "python"
	requirements.ExpectedPackageManager = "requirements"
	requirements.ExpectedLockFormat = "requirements-direct"
	bun := testCase("bun-contract")
	bun.ExpectedPackageManager = "bun"
	bun.ExpectedLockFormat = "bun-text"
	bun.Scenarios[0].Expect = Expectation{
		AllowedStatuses: []string{"partial"}, AllowedExits: []int{6}, AllowPartial: true,
		Capabilities: []ExpectedCapability{{
			Name: "package_updates", Status: "unavailable", ReasonCode: "toolchain_incompatible",
		}},
		FailedStages: []ExpectedFailure{{
			Stage: "candidate", ReasonCode: "toolchain_incompatible",
		}},
	}
	scanner := &fakeScanner{results: []fakeScanResult{
		{output: `{"format":1,"command":"scan","config":{"detected_stacks":["python"]},"results":[{"status":"scan_only","stages":[{"name":"candidate","status":"succeeded"}],"diagnostics":[{"file":"requirements.txt","line":2,"code":"exact_pin_required","severity":"info","message":"expected one exact pin"}],"warnings":[],"package_updates":{"status":"scan_only","reason":"manifest_has_no_safe_mutation_contract"},"toolchain":{"package_manager":"requirements","lock_formats":["requirements-direct"]}}],"warnings":[],"errors":[]}`},
		{exit: 6, output: `{"format":1,"command":"scan","config":{"detected_stacks":["node"]},"results":[{"status":"partial","stages":[{"name":"candidate","status":"failed","reason":"scanner unavailable"}],"diagnostics":[],"warnings":[],"error":{"code":"toolchain_incompatible","message":"scanner unavailable","stage":"candidate"},"package_updates":{"status":"unavailable","reason":"toolchain_incompatible"},"toolchain":{"package_manager":"bun","lock_formats":["bun-text"]}}],"warnings":[],"errors":[]}`},
	}}
	report, _, exit, err := (Harness{Sources: &fakeSources{}, Scanner: scanner}).Execute(
		context.Background(),
		HarnessInput{
			Root: root, ManifestBytes: []byte("manifest"),
			Stable: []Case{requirements, bun},
			Now:    time.Date(2026, 7, 27, 4, 0, 0, 0, time.UTC),
		},
	)
	if err != nil || exit != 0 {
		t.Fatalf("Execute() = exit %d, err %v", exit, err)
	}
	if report.Summary.StablePassed != 2 || report.Summary.StableFailed != 0 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	if report.Results[0].Verdict != "pass" || report.Results[1].ObservedCategory != "expected-partial" {
		t.Fatalf("results = %#v", report.Results)
	}
}

func TestHarnessWarnsWhenStableSelectionIsNotComparable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	selected := testCase("selected")
	report, _, exit, err := (Harness{
		Sources: &fakeSources{},
		Scanner: &fakeScanner{results: []fakeScanResult{{output: cleanEnvelope}}},
	}).Execute(context.Background(), HarnessInput{
		Root: root, ManifestBytes: []byte("manifest"),
		Stable:         []Case{selected},
		ExpectedStable: []Case{selected, testCase("not-selected")},
		Now:            time.Date(2026, 7, 27, 5, 0, 0, 0, time.UTC),
	})
	if err != nil || exit != 0 {
		t.Fatalf("Execute() = exit %d, err %v", exit, err)
	}
	if !slicesContains(report.Warnings, "current report excluded from comparison: stable result set is incomplete") {
		t.Fatalf("warnings = %#v", report.Warnings)
	}
	if report.Comparison.PreviousRunID != "" {
		t.Fatalf("comparison = %#v", report.Comparison)
	}
}

func addOnboarding(root string) error {
	if err := os.WriteFile(filepath.Join(root, ".vuelta.yaml"), []byte("schema_version: 1\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, ".gitignore"), []byte("/.vuelta/\n"), 0o600)
}
