package ecosystem

import (
	"os"
	"path/filepath"
	"testing"
)

type referenceAdapter struct {
	testAdapter
}

func (referenceAdapter) Detect(root string) (bool, error) {
	return IsRegularRootFile(root, "example.lock"), nil
}

func (referenceAdapter) PackageInput(bool) InputContract {
	return InputContract{Stage: InputStagePackageCandidates, Files: []InputFile{
		{Path: "example.toml", Category: InputCategoryManifest},
		{Path: "example.lock", Category: InputCategoryLock},
	}}
}

func (a referenceAdapter) DependencyInput() InputContract {
	contract := a.PackageInput(false)
	contract.Stage = InputStageDependencyCVE
	return contract
}

func (a referenceAdapter) Scanner(ScannerRequest) (ScannerSpec, error) {
	return ScannerSpec{Kind: a.key.PackageManager, ExpectedScanner: "example-scan", Args: []string{"example-scan", "--json"}}, nil
}

func (a referenceAdapter) DecodeCandidates([]byte, map[string][]byte) (CandidateReport, error) {
	return CandidateReport{Candidates: []Candidate{{
		Kind: a.key.PackageManager, Name: "demo", Current: "1.0.0", Target: "2.0.0",
	}}}, nil
}

func (a referenceAdapter) PlannedMutation(request PlannedMutationRequest) (PlannedMutationSpec, error) {
	return PlannedMutationSpec{
		LockFile: "example.lock", LegacyImageKey: "example",
		Mutations: []CandidateMutation{{Candidate: request.Candidates[0], Commands: [][]string{{"example", "update", request.Candidates[0].Name + "@" + request.Candidates[0].Target}}}},
	}, nil
}

func TestReferenceAdapterConnectsWithoutProductionCatalogChanges(t *testing.T) {
	t.Parallel()
	key, err := NewKey("example", "manager")
	if err != nil {
		t.Fatal(err)
	}
	adapter := referenceAdapter{testAdapter: testAdapter{key: key, metadata: Metadata{Version: "1"}}}
	registry, err := NewRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "example.lock"), []byte("locked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if detected, err := adapter.Detect(root); err != nil || !detected {
		t.Fatalf("reference detection = %t, %v", detected, err)
	}
	resolved, err := registry.Lookup("example", "manager")
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := resolved.(ScannerProvider).Scanner(ScannerRequest{})
	if err != nil || len(scanner.Args) == 0 {
		t.Fatalf("reference scanner = %#v, %v", scanner, err)
	}
	report, err := resolved.(CandidateDecoder).DecodeCandidates([]byte(`{}`), nil)
	if err != nil || len(report.Candidates) != 1 {
		t.Fatalf("reference candidates = %#v, %v", report, err)
	}
	plan, err := resolved.(PlannedMutationProvider).PlannedMutation(PlannedMutationRequest{Candidates: report.Candidates})
	if err != nil || filepath.Base(plan.LockFile) != plan.LockFile || len(plan.Mutations) != 1 {
		t.Fatalf("reference mutation = %#v, %v", plan, err)
	}
}
