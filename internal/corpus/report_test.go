package corpus

import (
	"errors"
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
		{name: "success", source: "stable", envelope: ObservedEnvelope{Statuses: []string{"clean"}}, want: "pass"},
		{name: "findings", source: "stable", exit: 5, envelope: ObservedEnvelope{Statuses: []string{"findings"}}, want: "pass"},
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
		AllowPartial: true, AllowedExits: []int{6},
		Capabilities: []ExpectedCapability{{Name: "package_updates", Status: "unavailable", ReasonContains: "scanner"}},
	}
	envelope := ObservedEnvelope{
		Statuses:     []string{"partial"},
		Capabilities: []ObservedCapability{{Name: "package_updates", Status: "unavailable", Reason: "scanner is unavailable"}},
	}
	category, verdict, _ := Classify("stable", 6, envelope, expectation, nil)
	if category != "expected-partial" || verdict != "pass" {
		t.Fatalf("Classify() = %q, %q; want expected-partial, pass", category, verdict)
	}
	_, verdict, _ = Classify("stable", 0, envelope, expectation, nil)
	if verdict != "fail" {
		t.Fatal("Classify() accepted a partial capability contract with the wrong exit code")
	}
}

func TestParseObservedEnvelopeRejectsBrokenJSON(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"format":1,"command":"scan","config":{"detected_stacks":["node"]},"results":[{"status":"clean","stages":[],"diagnostics":[],"warnings":[],"capabilities":[],"toolchain":{"package_manager":"npm","lock_formats":["npm-v3"]}}],"warnings":[],"errors":[]}`)
	observed, err := ParseObservedEnvelope(valid)
	if err != nil {
		t.Fatalf("ParseObservedEnvelope() error = %v", err)
	}
	if len(observed.Statuses) != 1 || observed.Statuses[0] != "clean" {
		t.Fatalf("statuses = %#v", observed.Statuses)
	}
	if len(observed.Toolchains) != 1 || observed.Toolchains[0].PackageManager != "npm" {
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
