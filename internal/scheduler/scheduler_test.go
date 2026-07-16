package scheduler

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	responses []Invocation
	calls     [][]string
}

func (r *fakeRunner) Run(_ context.Context, args []string) Invocation {
	r.calls = append(r.calls, append([]string(nil), args...))
	if len(r.responses) == 0 {
		return Invocation{ExitCode: ExitFailure, Err: errors.New("unexpected invocation")}
	}
	response := r.responses[0]
	r.responses = r.responses[1:]
	return response
}

func TestRunContinuesAfterPartialScanAndUpdateFailure(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{
		{Stdout: fixture(t, "scan-partial.json"), ExitCode: ExitFailure},
		{Stdout: updateFixture(t, "update-failure.json", "snapshot-api"), ExitCode: ExitFailure},
		{Stdout: updateFixture(t, "update-success.json", "snapshot-worker"), ExitCode: ExitOK},
	}}
	report, exitCode := Run(context.Background(), runner, Options{
		ConfigPath: "/etc/vuelta/config.yaml", FailurePolicy: FailureContinue, FindingsPolicy: FindingsReport,
	})

	if exitCode != ExitFailure {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitFailure)
	}
	if report.Summary != (Summary{Ready: 2, Updated: 1, Failed: 1, Clean: 1, ScanFailed: 1}) {
		t.Fatalf("summary = %#v", report.Summary)
	}
	if len(report.ScanResults) != 4 || report.ScanResults[2].Project != "web" || report.ScanResults[2].Status != "failed" || report.ScanResults[2].Error.Code != "dirty_worktree" {
		t.Fatalf("scan results = %#v", report.ScanResults)
	}
	wantCalls := [][]string{
		{"--config", "/etc/vuelta/config.yaml", "scan", "--all", "--json"},
		{"--config", "/etc/vuelta/config.yaml", "update", "--yes", "--json", "snapshot-api"},
		{"--config", "/etc/vuelta/config.yaml", "update", "--yes", "--json", "snapshot-worker"},
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, wantCalls)
	}
}

func TestRunStopPolicyDoesNotApplyPartialScanSnapshots(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{{Stdout: fixture(t, "scan-partial.json"), ExitCode: ExitFailure}}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureStop, FindingsPolicy: FindingsReport})
	if exitCode != ExitFailure || len(runner.calls) != 1 || report.Summary.NotAttempted != 2 {
		t.Fatalf("exit=%d calls=%#v report=%#v", exitCode, runner.calls, report)
	}
}

func TestRunFindingsOnlyStillAppliesReadySnapshots(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{
		{Stdout: fixture(t, "scan-ready.json"), ExitCode: ExitFindings},
		{Stdout: updateFixture(t, "update-success.json", "snapshot-api"), ExitCode: ExitOK},
	}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureContinue, FindingsPolicy: FindingsFail})
	if exitCode != ExitFindings || report.Summary.Updated != 1 {
		t.Fatalf("exit=%d report=%#v", exitCode, report)
	}
	wantScan := []string{"scan", "--all", "--json", "--fail-on", "vulnerabilities"}
	if !reflect.DeepEqual(runner.calls[0], wantScan) {
		t.Fatalf("scan args = %#v, want %#v", runner.calls[0], wantScan)
	}
}

func TestRunStopPolicyStopsAfterUpdateFailure(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{
		{Stdout: fixture(t, "scan-two-ready.json"), ExitCode: ExitOK},
		{Stdout: updateFixture(t, "update-failure.json", "snapshot-api"), ExitCode: ExitFailure},
	}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureStop, FindingsPolicy: FindingsReport})
	if exitCode != ExitFailure || len(runner.calls) != 2 || report.Summary.NotAttempted != 1 {
		t.Fatalf("exit=%d calls=%#v report=%#v", exitCode, runner.calls, report)
	}
}

func TestRunRejectsHumanOutputWithoutStartingUpdates(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{{Stdout: []byte("api: snapshot abc\n"), ExitCode: ExitOK}}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureContinue, FindingsPolicy: FindingsReport})
	if exitCode != ExitFailure || len(runner.calls) != 1 || len(report.Errors) != 1 || report.Errors[0].Code != "invalid_scan_json" {
		t.Fatalf("exit=%d calls=%#v report=%#v", exitCode, runner.calls, report)
	}
}

func TestRunCancellationDoesNotStartAnotherUpdate(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{
		{Stdout: fixture(t, "scan-partial.json"), ExitCode: ExitOK},
		{ExitCode: ExitInterrupted, Err: context.Canceled},
	}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureContinue, FindingsPolicy: FindingsReport})
	if exitCode != ExitInterrupted || len(runner.calls) != 2 || report.Results[0].Status != "cancelled" {
		t.Fatalf("exit=%d calls=%#v report=%#v", exitCode, runner.calls, report)
	}
}

func TestRunAlreadyCancelledDoesNotStartScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{}
	report, exitCode := Run(ctx, runner, Options{FailurePolicy: FailureContinue, FindingsPolicy: FindingsReport})
	if exitCode != ExitInterrupted || len(runner.calls) != 0 || len(report.Errors) != 1 {
		t.Fatalf("exit=%d calls=%#v report=%#v", exitCode, runner.calls, report)
	}
}

func TestRunRejectsSuccessfulMismatchedUpdateEnvelope(t *testing.T) {
	runner := &fakeRunner{responses: []Invocation{
		{Stdout: fixture(t, "scan-ready.json"), ExitCode: ExitOK},
		{Stdout: updateFixture(t, "update-success.json", "different-snapshot"), ExitCode: ExitOK},
	}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureContinue, FindingsPolicy: FindingsReport})
	if exitCode != ExitFailure || report.Summary.Failed != 1 || len(report.Errors) != 1 {
		t.Fatalf("exit=%d report=%#v", exitCode, report)
	}
}

func TestRunRejectsDuplicateSnapshotWithoutApplyingItTwice(t *testing.T) {
	scan := strings.Replace(string(fixture(t, "scan-two-ready.json")), "snapshot-worker", "snapshot-api", 1)
	runner := &fakeRunner{responses: []Invocation{
		{Stdout: []byte(scan), ExitCode: ExitOK},
		{Stdout: updateFixture(t, "update-success.json", "snapshot-api"), ExitCode: ExitOK},
	}}
	report, exitCode := Run(context.Background(), runner, Options{FailurePolicy: FailureContinue, FindingsPolicy: FindingsReport})
	if exitCode != ExitFailure || len(runner.calls) != 2 || report.Summary.Ready != 1 || len(report.Errors) != 1 {
		t.Fatalf("exit=%d calls=%#v report=%#v", exitCode, runner.calls, report)
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func updateFixture(t *testing.T, name, snapshotID string) []byte {
	t.Helper()
	return []byte(strings.ReplaceAll(string(fixture(t, name)), "SNAPSHOT_ID", snapshotID))
}
