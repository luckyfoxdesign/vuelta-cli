package corpus

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// HarnessInput contains already validated stable and discovery cases.
type HarnessInput struct {
	Root           string
	ManifestBytes  []byte
	Stable         []Case
	ExpectedStable []Case
	Discovery      []Case
	AppRevision    string
	Now            time.Time
	Warnings       []string
}

// Harness executes cases sequentially and never turns discovery findings into
// a failing stable exit status.
type Harness struct {
	Sources SourcePreparer
	Scanner Scanner
}

// Execute runs preflight once, scans every case despite case-local failures,
// writes both reports, and returns the stable regression exit status.
func (h Harness) Execute(ctx context.Context, input HarnessInput) (Report, string, int, error) {
	if h.Sources == nil || h.Scanner == nil {
		return Report{}, "", 2, errors.New("corpus harness dependencies are incomplete")
	}
	if input.Now.IsZero() {
		input.Now = time.Now()
	}
	storage, err := CreateRunStorage(input.Root, input.Now)
	if err != nil {
		return Report{}, "", 2, err
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion, RunID: storage.RunID, StartedAt: input.Now,
		AppRevision:  SanitizeMessage(input.AppRevision),
		ManifestHash: fmt.Sprintf("%x", sha256.Sum256(input.ManifestBytes)),
		Warnings:     uniqueSorted(input.Warnings), Results: []Result{},
		Comparison: Comparison{NewFailures: []string{}, Fixed: []string{}, Unchanged: []string{}, Slower: []string{}},
	}
	environment, preflightErr := h.Scanner.Preflight(ctx, storage.TempDir)
	if preflightErr != nil {
		report.Results = append(report.Results, infrastructureFailure(preflightErr))
		report.Summary.StableFailed = 1
		report.FinishedAt = time.Now()
		cleanupErr := storage.CleanupTemp()
		if cleanupErr != nil {
			report.Warnings = append(report.Warnings, SanitizeMessage(cleanupErr.Error()))
		}
		if err := storage.WriteReport(report); err != nil {
			return report, storage.RunDir, 1, err
		}
		return report, storage.RunDir, 1, nil
	}
	report.Environment = environment
	for _, selected := range []struct {
		source string
		cases  []Case
	}{{source: "stable", cases: input.Stable}, {source: "discovery", cases: input.Discovery}} {
		for _, corpusCase := range selected.cases {
			results, warnings := h.runCase(ctx, storage, selected.source, corpusCase)
			report.Results = append(report.Results, results...)
			report.Warnings = append(report.Warnings, warnings...)
		}
	}
	report.Warnings = uniqueSorted(report.Warnings)
	report.Summary = summarize(report.Results)
	expectedStable := input.ExpectedStable
	if expectedStable == nil {
		expectedStable = input.Stable
	}
	if reason := ComparisonIneligibility(report, expectedStable, report.ManifestHash); reason != "" {
		report.Warnings = append(report.Warnings, "current report excluded from comparison: "+reason)
	} else if previous, ok, comparisonWarnings, previousErr := PreviousComparableReport(
		input.Root, storage.RunID, expectedStable, report.ManifestHash,
	); previousErr != nil {
		report.Warnings = append(report.Warnings, "previous report comparison failed: "+SanitizeMessage(previousErr.Error()))
	} else {
		report.Warnings = append(report.Warnings, comparisonWarnings...)
		if ok {
			report.Comparison = BuildComparison(report, previous)
			applyDurationComparison(report.Results, previous.Results)
		}
	}
	report.FinishedAt = time.Now()
	if cleanupErr := storage.CleanupTemp(); cleanupErr != nil {
		report.Warnings = append(report.Warnings, "temporary work cleanup failed: "+SanitizeMessage(cleanupErr.Error()))
		report.Summary.StableFailed++
	}
	report.Warnings = uniqueSorted(report.Warnings)
	if err := storage.WriteReport(report); err != nil {
		return report, storage.RunDir, 1, err
	}
	if report.Summary.StableFailed > 0 {
		return report, storage.RunDir, 1, nil
	}
	return report, storage.RunDir, 0, nil
}

func (h Harness) runCase(ctx context.Context, storage RunStorage, source string, corpusCase Case) (results []Result, warnings []string) {
	prepared, err := h.Sources.Prepare(ctx, storage.Root, storage.TempDir, corpusCase)
	if err != nil {
		return []Result{caseFailure(source, corpusCase, "source-failure", err)}, nil
	}
	if prepared.CacheHit {
		warnings = append(warnings, corpusCase.Name+": immutable source cache hit")
	}
	defer func() {
		if cleanupErr := prepared.Cleanup(); cleanupErr != nil {
			warnings = append(warnings, corpusCase.Name+": work copy cleanup failed: "+SanitizeMessage(cleanupErr.Error()))
		}
	}()
	initial, err := SnapshotSource(prepared.Root)
	if err != nil {
		return []Result{caseFailure(source, corpusCase, "source-snapshot-failure", err)}, warnings
	}
	for _, scenario := range corpusCase.Scenarios {
		for pass := 1; pass <= scenario.EffectiveRepeat(); pass++ {
			result := h.runPass(ctx, storage, source, corpusCase, prepared, initial, scenario, pass)
			results = append(results, result)
		}
	}
	return results, warnings
}

func (h Harness) runPass(
	ctx context.Context,
	storage RunStorage,
	source string,
	corpusCase Case,
	prepared PreparedSource,
	initial SourceSnapshot,
	scenario Scenario,
	pass int,
) Result {
	request := ScanRequest{Directory: prepared.ScanRoot, Args: append([]string(nil), scenario.Args...)}
	observation, runErr := h.Scanner.Scan(ctx, request)
	processCompleted := runErr == nil
	var envelope ObservedEnvelope
	if runErr == nil {
		parsed, parseErr := ParseObservedEnvelope(observation.Stdout)
		if parseErr != nil {
			runErr = fmt.Errorf("%w: %v", ErrInvalidJSON, parseErr)
		} else {
			envelope = parsed
		}
	}
	category, verdict, reason := Classify(source, observation.ExitCode, envelope, scenario.Expect, runErr)
	if runErr == nil && verdict == "pass" {
		if contractErr := ValidateObservedContract(corpusCase, envelope); contractErr != nil {
			category, reason = "detection-contract-mismatch", SanitizeMessage(contractErr.Error())
			if source == "stable" {
				verdict = "fail"
			} else {
				verdict = "finding"
			}
		}
	}
	after, snapshotErr := SnapshotSource(prepared.Root)
	var onboarding, unexpected []string
	if snapshotErr != nil {
		category, reason = "source-snapshot-failure", SanitizeMessage(snapshotErr.Error())
		if source == "stable" {
			verdict = "fail"
		} else {
			verdict = "finding"
		}
	} else {
		onboarding, unexpected, snapshotErr = CompareSource(prepared.Root, prepared.ScanRoot, initial, after)
		if snapshotErr != nil {
			category, reason = "source-comparison-failure", SanitizeMessage(snapshotErr.Error())
			if source == "stable" {
				verdict = "fail"
			} else {
				verdict = "finding"
			}
		} else if len(unexpected) > 0 {
			category, reason = "unexpected-filesystem-change", "scan changed files outside Vuelta onboarding/private state"
			if source == "stable" {
				verdict = "fail"
			} else {
				verdict = "finding"
			}
		}
	}
	logName := logSlug(corpusCase.Name, scenario.Name, pass)
	logPath, logErr := storage.WriteLog(logName, observation)
	if logErr != nil {
		category, reason = "log-write-failure", SanitizeMessage(logErr.Error())
		if source == "stable" {
			verdict = "fail"
		} else {
			verdict = "finding"
		}
	}
	projectURL := corpusCase.URL
	commitURL := corpusCase.URL + "/commit/" + corpusCase.Commit
	var exitCode *int
	if processCompleted {
		exitCode = intPointer(observation.ExitCode)
	}
	argv := []string{"--no-input", "--no-color", "scan", "--directory", prepared.ScanRoot}
	argv = append(argv, scenario.Args...)
	argv = append(argv, "--json")
	return Result{
		Source: source, Name: corpusCase.Name, URL: corpusCase.URL, Commit: corpusCase.Commit,
		Subdir: corpusCase.Subdir, Scenario: scenario.Name, Pass: pass,
		Argv: argv, ExitCode: exitCode, DurationMS: observation.Duration.Milliseconds(),
		ObservedCategory: category, Verdict: verdict, Reason: SanitizeMessage(reason),
		Envelope: envelope, LogPath: logPath, ProjectURL: projectURL, CommitURL: commitURL,
		ReproduceCommand:  []string{"scripts/corpus-scan.sh", storage.Root, "--case", corpusCase.Name},
		UnexpectedChanges: unexpected, OnboardingChanges: onboarding,
		OutputTruncated: observation.Truncated, Contract: corpusCase,
	}
}

func infrastructureFailure(err error) Result {
	return Result{
		Source: "stable", Name: "preflight", Scenario: "preflight",
		ObservedCategory: "infrastructure-failure", Verdict: "fail",
		Reason: SanitizeMessage(err.Error()), Argv: []string{}, Envelope: emptyEnvelope(),
		ReproduceCommand: []string{}, UnexpectedChanges: []string{}, OnboardingChanges: []string{},
	}
}

func caseFailure(source string, corpusCase Case, category string, err error) Result {
	verdict := "fail"
	if source == "discovery" {
		verdict = "finding"
	}
	return Result{
		Source: source, Name: corpusCase.Name, URL: corpusCase.URL, Commit: corpusCase.Commit,
		Subdir: corpusCase.Subdir, Scenario: "source", ObservedCategory: category,
		Verdict: verdict, Reason: SanitizeMessage(err.Error()), Argv: []string{},
		Envelope: emptyEnvelope(), ProjectURL: corpusCase.URL,
		CommitURL:         corpusCase.URL + "/commit/" + corpusCase.Commit,
		ReproduceCommand:  []string{"scripts/corpus-scan.sh", "<ROOT>", "--case", corpusCase.Name},
		UnexpectedChanges: []string{}, OnboardingChanges: []string{}, Contract: corpusCase,
	}
}

func emptyEnvelope() ObservedEnvelope {
	return ObservedEnvelope{
		DetectedStacks: []string{}, PackageManagers: []string{}, LockFormats: []string{},
		Statuses: []string{}, Stages: []ObservedStage{}, Diagnostics: []string{},
		DiagnosticDetails: []ObservedDiagnostic{},
		Warnings:          []string{}, Errors: []ObservedError{}, Capabilities: []ObservedCapability{},
		Toolchains: []ObservedToolchain{},
	}
}

func logSlug(caseName, scenario string, pass int) string {
	return fmt.Sprintf("%s--%s--%d", caseName, scenario, pass)
}

func summarize(results []Result) Summary {
	type state struct {
		source string
		failed bool
	}
	cases := make(map[string]state)
	for _, result := range results {
		key := result.Source + "\x00" + result.Name
		current := cases[key]
		current.source = result.Source
		if result.Verdict == "fail" || result.Verdict == "finding" {
			current.failed = true
		}
		cases[key] = current
	}
	var summary Summary
	for _, current := range cases {
		if current.source == "stable" {
			if current.failed {
				summary.StableFailed++
			} else {
				summary.StablePassed++
			}
		} else if current.failed {
			summary.DiscoveryFindings++
		} else {
			summary.DiscoveryPassed++
		}
	}
	return summary
}

func applyDurationComparison(current, previous []Result) {
	old := stableResultMap(previous)
	for i := range current {
		key := resultKey(current[i])
		was, ok := old[key]
		if !ok || current[i].Source != "stable" {
			continue
		}
		current[i].ComparableDurationMS = was.DurationMS
		current[i].PerformanceRegression = was.DurationMS > 0 && current[i].DurationMS > was.DurationMS*2
	}
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		value = SanitizeMessage(value)
		if value != "" {
			seen[value] = true
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// SelectStableCases applies --case or --only-failed without changing order.
func SelectStableCases(cases []Case, caseName string, failed map[string]bool) ([]Case, error) {
	if caseName != "" && len(failed) > 0 {
		return nil, errors.New("--case and --only-failed are mutually exclusive")
	}
	var selected []Case
	for _, corpusCase := range cases {
		if caseName != "" && corpusCase.Name != caseName {
			continue
		}
		if len(failed) > 0 && !failed[corpusCase.Name] {
			continue
		}
		selected = append(selected, corpusCase)
	}
	if caseName != "" && len(selected) == 0 {
		return nil, fmt.Errorf("stable corpus case %q was not found", caseName)
	}
	return selected, nil
}

// FailedStableCases extracts stable case names from a previous report.
func FailedStableCases(report Report) map[string]bool {
	failed := make(map[string]bool)
	for _, result := range report.Results {
		if result.Source == "stable" && result.Verdict == "fail" && result.Name != "preflight" {
			failed[result.Name] = true
		}
	}
	return failed
}

// DiscoveryCaseFromReports finds a recorded discovery contract by name.
func DiscoveryCaseFromReports(root, name string) (Case, bool, error) {
	entries, err := os.ReadDir(filepath.Join(root, "runs"))
	if err != nil {
		if os.IsNotExist(err) {
			return Case{}, false, nil
		}
		return Case{}, false, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	for _, id := range ids {
		report, loadErr := LoadReport(filepath.Join(root, "runs", id, "report.json"))
		if loadErr != nil {
			continue
		}
		for _, result := range report.Results {
			if result.Source == "discovery" && result.Name == name {
				if err := result.Contract.validate(false); err != nil {
					return Case{}, false, fmt.Errorf("recorded discovery contract is invalid: %w", err)
				}
				return result.Contract, true, nil
			}
		}
	}
	return Case{}, false, nil
}

// MarshalCandidateManifest renders a deterministic candidate manifest.
func MarshalCandidateManifest(cases []Case) ([]byte, error) {
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Cases: append([]Case(nil), cases...)}
	if err := manifest.Validate(true); err != nil {
		return nil, err
	}
	return yaml.Marshal(manifest)
}

func intPointer(value int) *int { return &value }
