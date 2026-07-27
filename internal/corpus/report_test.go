package corpus

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassifyExitAndStructuredFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		exit     int
		envelope ObservedEnvelope
		runErr   error
		want     string
	}{
		{name: "success", source: "stable", envelope: ObservedEnvelope{
			Statuses: []string{"clean"}, Capabilities: packageUpdatesForStatus("available"),
		}, want: "pass"},
		{name: "findings", source: "stable", exit: 5, envelope: ObservedEnvelope{
			Statuses: []string{"findings"}, Capabilities: packageUpdatesForStatus("available"),
		}, want: "pass"},
		{name: "missing package capability", source: "stable", envelope: ObservedEnvelope{
			Statuses: []string{"clean"},
		}, want: "fail"},
		{name: "config", source: "stable", exit: 4, envelope: ObservedEnvelope{}, want: "fail"},
		{name: "partial", source: "stable", exit: 6, envelope: ObservedEnvelope{}, want: "fail"},
		{name: "image", source: "stable", exit: 7, envelope: ObservedEnvelope{}, want: "fail"},
		{name: "failed stage", source: "stable", envelope: ObservedEnvelope{Stages: []ObservedStage{{Status: "failed"}}}, want: "fail"},
		{name: "error status", source: "stable", envelope: ObservedEnvelope{Statuses: []string{"error"}}, want: "fail"},
		{name: "discovery failure", source: "discovery", exit: 4, envelope: ObservedEnvelope{}, want: "finding"},
		{name: "timeout", source: "stable", runErr: ErrTimeout, want: "fail"},
		{name: "oversized", source: "stable", runErr: ErrOutputTooLarge, want: "fail"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, verdict, _ := Classify(test.source, test.exit, test.envelope, Expectation{}, test.runErr)
			if verdict != test.want {
				t.Fatalf("Classify() verdict = %q, want %q", verdict, test.want)
			}
		})
	}
}

func TestClassifyExactPartialCapability(t *testing.T) {
	t.Parallel()
	expectation := Expectation{
		AllowPartial: true, AllowedExits: []int{6}, AllowedStatuses: []string{"partial"},
		Capabilities: []ExpectedCapability{{
			Name: "package_updates", Status: "unavailable", ReasonCode: "toolchain_incompatible",
		}},
		FailedStages: []ExpectedFailure{{
			Stage: "candidate", ReasonCode: "toolchain_incompatible",
		}},
	}
	envelope := ObservedEnvelope{
		Statuses: []string{"partial"},
		Stages:   []ObservedStage{{Name: "candidate", Status: "failed", Reason: "scanner is unavailable"}},
		Errors: []ObservedError{{
			Code: "toolchain_incompatible", Stage: "candidate", Message: "scanner is unavailable",
		}},
		Capabilities: []ObservedCapability{{
			Name: "package_updates", Status: "unavailable", Reason: "toolchain_incompatible",
		}},
	}
	category, verdict, _ := Classify("stable", 6, envelope, expectation, nil)
	if category != "expected-partial" || verdict != "pass" {
		t.Fatalf("Classify() = %q, %q; want expected-partial, pass", category, verdict)
	}
	tests := []struct {
		name   string
		exit   int
		mutate func(*ObservedEnvelope)
	}{
		{name: "wrong exit", exit: 0},
		{name: "wrong status", exit: 6, mutate: func(value *ObservedEnvelope) {
			value.Statuses = []string{"clean"}
		}},
		{name: "missing capability", exit: 6, mutate: func(value *ObservedEnvelope) {
			value.Capabilities = nil
		}},
		{name: "wrong reason code", exit: 6, mutate: func(value *ObservedEnvelope) {
			value.Capabilities[0].Reason = "package_scan_failed"
		}},
		{name: "additional failed stage", exit: 6, mutate: func(value *ObservedEnvelope) {
			value.Stages = append(value.Stages, ObservedStage{Name: "vulnerability", Status: "failed"})
			value.Errors = append(value.Errors, ObservedError{
				Code: "vulnerability_scan_failed", Stage: "vulnerability",
			})
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := envelope
			candidate.Statuses = append([]string(nil), envelope.Statuses...)
			candidate.Stages = append([]ObservedStage(nil), envelope.Stages...)
			candidate.Errors = append([]ObservedError(nil), envelope.Errors...)
			candidate.Capabilities = append([]ObservedCapability(nil), envelope.Capabilities...)
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			_, got, _ := Classify("stable", test.exit, candidate, expectation, nil)
			if got != "fail" {
				t.Fatal("Classify() accepted a mismatched partial contract")
			}
		})
	}
}

func TestClassifyCanonicalStatuses(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"clean", "ready", "findings", "scan_only"} {
		status := status
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			exit := 0
			if status == "findings" {
				exit = 5
			}
			capabilityStatus := "available"
			if status == "scan_only" {
				capabilityStatus = "scan_only"
			}
			_, verdict, _ := Classify("stable", exit, ObservedEnvelope{
				Statuses: []string{status}, Capabilities: packageUpdatesForStatus(capabilityStatus),
			}, Expectation{}, nil)
			if verdict != "pass" {
				t.Fatalf("status %q verdict = %q, want pass", status, verdict)
			}
		})
	}
	for _, status := range []string{"scan-only", "unknown"} {
		_, verdict, _ := Classify(
			"stable", 0, ObservedEnvelope{Statuses: []string{status}}, Expectation{}, nil,
		)
		if verdict != "fail" {
			t.Fatalf("status %q verdict = %q, want fail", status, verdict)
		}
	}
}

func TestClassifyTypedDiagnostics(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		severity string
		want     string
	}{
		{name: "informational", severity: "info", want: "pass"},
		{name: "fatal", severity: "error", want: "fail"},
		{name: "unknown fails closed", severity: "", want: "fail"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			envelope := ObservedEnvelope{
				Statuses:    []string{"scan_only"},
				Diagnostics: []string{"requirements: unsupported line"},
				Capabilities: []ObservedCapability{{
					Name: "package_updates", Status: "scan_only",
					Reason: "manifest_has_no_safe_mutation_contract",
				}},
				DiagnosticDetails: []ObservedDiagnostic{{
					Code: "exact_pin_required", Severity: test.severity,
					Message: "requirements: unsupported line",
				}},
			}
			_, verdict, _ := Classify("stable", 0, envelope, Expectation{}, nil)
			if verdict != test.want {
				t.Fatalf("Classify() verdict = %q, want %q", verdict, test.want)
			}
		})
	}
}

func packageUpdatesForStatus(status string) []ObservedCapability {
	reason := ""
	if status == "scan_only" {
		reason = "manifest_has_no_safe_mutation_contract"
	}
	return []ObservedCapability{{Name: "package_updates", Status: status, Reason: reason}}
}

func TestParseObservedEnvelopeRejectsBrokenJSON(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"format":1,"command":"scan","config":{"detected_stacks":["node"]},"results":[{"status":"clean","stages":[],"diagnostics":[],"warnings":[],"capabilities":[],"toolchain":{"source":"default","runtime_constraint":">=18.0.0","runtime":"24","package_manager":"npm","lock_formats":["npm-v3"]}}],"warnings":[],"errors":[]}`)
	observed, err := ParseObservedEnvelope(valid)
	if err != nil {
		t.Fatalf("ParseObservedEnvelope() error = %v", err)
	}
	if len(observed.Statuses) != 1 || observed.Statuses[0] != "clean" {
		t.Fatalf("statuses = %#v", observed.Statuses)
	}
	if len(observed.Toolchains) != 1 || observed.Toolchains[0].PackageManager != "npm" ||
		observed.Toolchains[0].RuntimeConstraint != ">=18.0.0" ||
		observed.Toolchains[0].Runtime != "24" ||
		observed.Toolchains[0].Source != "default" {
		t.Fatalf("toolchains = %#v", observed.Toolchains)
	}
	corpusCase := testCase("contract")
	if err := ValidateObservedContract(corpusCase, observed); err != nil {
		t.Fatalf("ValidateObservedContract() error = %v", err)
	}
	corpusCase.ExpectedPackageManager = "pnpm"
	if err := ValidateObservedContract(corpusCase, observed); err == nil {
		t.Fatal("ValidateObservedContract() accepted the wrong manager")
	}
	corpusCase.ExpectedPackageManager = "npm"
	observed.DetectedStacks = nil
	if err := ValidateObservedContract(corpusCase, observed); err != nil {
		t.Fatalf("ValidateObservedContract() rejected stack inferred from selected manager: %v", err)
	}
	corpusCase.Features = []string{"discovery"}
	corpusCase.ExpectedLockFormat = "npm-detected"
	if err := ValidateObservedContract(corpusCase, observed); err != nil {
		t.Fatalf("ValidateObservedContract() rejected a discovery lock format: %v", err)
	}
	for _, input := range [][]byte{[]byte(`{`), append(valid, []byte(` {}`)...)} {
		if _, err := ParseObservedEnvelope(input); err == nil {
			t.Fatalf("ParseObservedEnvelope(%q) accepted invalid input", input)
		}
	}
}

func TestParseRequirementsEnvelopePreservesInformationalDiagnostics(t *testing.T) {
	t.Parallel()
	data := []byte(`{"format":1,"command":"scan","config":{"detected_stacks":["python"]},"results":[{"status":"scan_only","stages":[{"name":"candidate","status":"succeeded"}],"diagnostics":[{"file":"requirements.txt","line":2,"code":"exact_pin_required","severity":"info","message":"expected one exact pin"}],"warnings":[],"capabilities":[],"package_updates":{"status":"scan_only","reason":"manifest_has_no_safe_mutation_contract"},"toolchain":{"package_manager":"requirements","lock_formats":["requirements-direct"]}}],"warnings":[],"errors":[]}`)
	observed, err := ParseObservedEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.DiagnosticDetails) != 1 ||
		observed.DiagnosticDetails[0].Severity != "info" ||
		len(observed.Capabilities) != 1 {
		t.Fatalf("observed envelope = %#v", observed)
	}
	_, verdict, _ := Classify("stable", 0, observed, Expectation{}, nil)
	if verdict != "pass" {
		t.Fatalf("informational requirements envelope verdict = %q, want pass", verdict)
	}
}

func TestSanitizeAndRenderMarkdown(t *testing.T) {
	t.Parallel()
	value := SanitizeMessage("bad\x00\n| `value`")
	if strings.ContainsRune(value, '\x00') || strings.ContainsRune(value, '\n') {
		t.Fatalf("SanitizeMessage() = %q", value)
	}
	report := Report{
		RunID: "run", Results: []Result{{
			Source: "stable", Name: "a|b", Scenario: "default", Pass: 1,
			ExitCode: intPointer(1), Verdict: "fail", Reason: "`bad`",
		}},
	}
	markdown := RenderMarkdown(report)
	if strings.Contains(markdown, "| [a|b]") || strings.Contains(markdown, "| `bad` |") {
		t.Fatalf("RenderMarkdown() did not escape cells:\n%s", markdown)
	}
}

func TestBuildComparison(t *testing.T) {
	t.Parallel()
	previous := Report{RunID: "old", Results: []Result{
		{Source: "stable", Name: "fixed", Scenario: "default", Pass: 1, Verdict: "fail", DurationMS: 10},
		{Source: "stable", Name: "regressed", Scenario: "default", Pass: 1, Verdict: "pass", DurationMS: 10},
	}}
	current := Report{Results: []Result{
		{Source: "stable", Name: "fixed", Scenario: "default", Pass: 1, Verdict: "pass", DurationMS: 30},
		{Source: "stable", Name: "regressed", Scenario: "default", Pass: 1, Verdict: "fail", DurationMS: 10},
	}}
	got := BuildComparison(current, previous)
	if len(got.Fixed) != 1 || len(got.NewFailures) != 1 || len(got.Slower) != 1 {
		t.Fatalf("BuildComparison() = %#v", got)
	}
}

func TestComparisonIneligibility(t *testing.T) {
	t.Parallel()
	stable := []Case{testCase("complete")}
	base := Report{
		SchemaVersion: ReportSchemaVersion, ManifestHash: "manifest",
		Results: []Result{{
			Source: "stable", Name: "complete", Scenario: "default", Pass: 1, Verdict: "pass",
		}},
	}
	if reason := ComparisonIneligibility(base, stable, "manifest"); reason != "" {
		t.Fatalf("complete report excluded: %s", reason)
	}
	tests := []struct {
		name   string
		report Report
		hash   string
	}{
		{name: "preflight only", hash: "manifest", report: Report{
			SchemaVersion: ReportSchemaVersion, ManifestHash: "manifest",
			Results: []Result{{Source: "stable", Name: "preflight", Scenario: "preflight"}},
		}},
		{name: "manifest mismatch", hash: "other", report: base},
		{name: "incomplete selection", hash: "manifest", report: Report{
			SchemaVersion: ReportSchemaVersion, ManifestHash: "manifest", Results: []Result{},
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if reason := ComparisonIneligibility(test.report, stable, test.hash); reason == "" {
				t.Fatal("ineligible report was accepted")
			}
		})
	}
}

func TestPreviousComparableReportSkipsPreflightOnlyRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	stable := []Case{testCase("complete")}
	finished := time.Date(2026, 7, 27, 1, 0, 0, 0, time.UTC)

	fullStorage, err := CreateRunStorage(root, finished)
	if err != nil {
		t.Fatal(err)
	}
	full := Report{
		SchemaVersion: ReportSchemaVersion, RunID: fullStorage.RunID,
		ManifestHash: "manifest", FinishedAt: finished,
		Results: []Result{{
			Source: "stable", Name: "complete", Scenario: "default", Pass: 1, Verdict: "pass",
		}},
	}
	if err := fullStorage.WriteReport(full); err != nil {
		t.Fatal(err)
	}
	if err := fullStorage.CleanupTemp(); err != nil {
		t.Fatal(err)
	}

	preflightStorage, err := CreateRunStorage(root, finished.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	preflight := Report{
		SchemaVersion: ReportSchemaVersion, RunID: preflightStorage.RunID,
		ManifestHash: "manifest", FinishedAt: finished.Add(time.Hour),
		Results: []Result{{
			Source: "stable", Name: "preflight", Scenario: "preflight", Verdict: "fail",
		}},
	}
	if err := preflightStorage.WriteReport(preflight); err != nil {
		t.Fatal(err)
	}
	if err := preflightStorage.CleanupTemp(); err != nil {
		t.Fatal(err)
	}

	got, ok, warnings, err := PreviousComparableReport(
		root, finished.Add(2*time.Hour).Format("20060102-150405"), stable, "manifest",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.RunID != full.RunID {
		t.Fatalf("PreviousComparableReport() = %q, %t; want %q, true", got.RunID, ok, full.RunID)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "preflight") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestClassifyProcessErrorIsSanitized(t *testing.T) {
	t.Parallel()
	_, _, reason := Classify("stable", 0, ObservedEnvelope{}, Expectation{}, errors.New("bad\x00\nmessage"))
	if strings.ContainsAny(reason, "\x00\n") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestReportTimeRoundTripShape(t *testing.T) {
	t.Parallel()
	report := Report{SchemaVersion: 1, StartedAt: time.Unix(1, 0).UTC()}
	if report.SchemaVersion != ReportSchemaVersion {
		t.Fatal("report schema mismatch")
	}
}

func TestLoadReportReadsSchemaOneWithoutDiagnosticDetails(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "report.json")
	data := []byte(`{"schema_version":1,"run_id":"old-run","finished_at":"2026-07-27T00:00:00Z","results":[{"envelope":{"diagnostics":["legacy diagnostic"]}}]}`)
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := LoadReport(filename)
	if err != nil {
		t.Fatalf("LoadReport() rejected schema-1 report: %v", err)
	}
	if len(report.Results) != 1 || len(report.Results[0].Envelope.Diagnostics) != 1 ||
		len(report.Results[0].Envelope.DiagnosticDetails) != 0 {
		t.Fatalf("legacy report = %#v", report)
	}
}
