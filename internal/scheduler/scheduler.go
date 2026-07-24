// Package scheduler orchestrates the public scan and update CLI contract.
// It intentionally remains outside the vuelta command tree: each update
// receives one exact target directory and its reviewed snapshot ID.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
)

const (
	ExitOK          = 0
	ExitFailure     = 1
	ExitFindings    = 5
	ExitPartial     = 6
	ExitInterrupted = 130

	FailureContinue = "continue"
	FailureStop     = "stop"
	FindingsReport  = "report"
	FindingsFail    = "fail"
)

// Options defines the scheduler's explicit continuation and findings policy.
type Options struct {
	ConfigPath     string
	FailurePolicy  string
	FindingsPolicy string
}

// Invocation is the captured result of one vuelta CLI process.
type Invocation struct {
	Stdout   []byte
	ExitCode int
	Err      error
}

// Runner executes one vuelta CLI process.
type Runner interface {
	Run(context.Context, []string) Invocation
}

// ExecRunner runs the configured vuelta binary without a shell. Child stdout
// is captured for JSON decoding while diagnostics remain on the supplied
// stderr stream.
type ExecRunner struct {
	Path   string
	Stderr io.Writer
}

// stdoutMaxBytes is the hard cap on a child's JSON stdout (F5-MED-008). The
// envelope is metadata-only, so exceeding this means a broken or hostile
// child: the process is killed and the invocation fails deterministically
// instead of decoding a truncated document.
const stdoutMaxBytes = 8 << 20

// commandWaitDelay bounds how long Wait may block on inherited pipes after
// the context is cancelled.
const commandWaitDelay = 10 * time.Second

// Run executes one child process.
func (r ExecRunner) Run(ctx context.Context, args []string) Invocation {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(runCtx, r.Path, args...)
	command.WaitDelay = commandWaitDelay
	stdout := capio.NewLimit(stdoutMaxBytes, cancel)
	command.Stdout = stdout
	command.Stderr = r.Stderr
	err := command.Run()
	if ctx.Err() != nil {
		return Invocation{Stdout: stdout.Bytes(), ExitCode: ExitInterrupted, Err: ctx.Err()}
	}
	if stdout.Exceeded() {
		return Invocation{ExitCode: ExitFailure, Err: fmt.Errorf("child stdout exceeded %d bytes", stdoutMaxBytes)}
	}
	if err == nil {
		return Invocation{Stdout: stdout.Bytes(), ExitCode: ExitOK}
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return Invocation{Stdout: stdout.Bytes(), ExitCode: exitError.ExitCode()}
	}
	return Invocation{Stdout: stdout.Bytes(), ExitCode: ExitFailure, Err: err}
}

// Error is a stable scheduler error record.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// Result records one ready snapshot's update outcome.
type Result struct {
	Project    string `json:"project,omitempty"`
	Directory  string `json:"directory"`
	SnapshotID string `json:"snapshot_id"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
}

// ScanOutcome preserves one project's structured scan status, including a
// failure that did not produce a snapshot.
type ScanOutcome struct {
	Project    string `json:"project,omitempty"`
	Directory  string `json:"directory"`
	Status     string `json:"status"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	Error      *Error `json:"error,omitempty"`
}

// Summary aggregates scan and update outcomes.
type Summary struct {
	Ready        int `json:"ready"`
	Updated      int `json:"updated"`
	Failed       int `json:"failed"`
	Clean        int `json:"clean"`
	Findings     int `json:"findings"`
	ScanFailed   int `json:"scan_failed"`
	NotAttempted int `json:"not_attempted"`
}

// Report is the scheduler's single stdout JSON document.
type Report struct {
	Format       int           `json:"format"`
	Command      string        `json:"command"`
	ScanExitCode int           `json:"scan_exit_code"`
	ScanResults  []ScanOutcome `json:"scan_results"`
	Results      []Result      `json:"results"`
	Summary      Summary       `json:"summary"`
	Errors       []Error       `json:"errors"`
}

type commandEnvelope[T any] struct {
	Format  int     `json:"format"`
	Command string  `json:"command"`
	Results []T     `json:"results"`
	Errors  []Error `json:"errors"`
}

type updateResult struct {
	SnapshotID string `json:"snapshot_id"`
	Status     string `json:"status"`
}

// Run performs one scan and applies each ready snapshot according to options.
func Run(ctx context.Context, runner Runner, options Options) (Report, int) {
	report := Report{Format: 1, Command: "schedule", ScanResults: []ScanOutcome{}, Results: []Result{}, Errors: []Error{}}
	if err := validateOptions(options); err != nil {
		addError(&report, "invalid_policy", err)
		return report, ExitFailure
	}
	if ctx.Err() != nil {
		addError(&report, "interrupted", ctx.Err())
		return report, ExitInterrupted
	}

	scanArgs := withConfig(options.ConfigPath, "scan", "--all", "--json")
	if options.FindingsPolicy == FindingsFail {
		scanArgs = append(scanArgs, "--fail-on", "vulnerabilities")
	}
	scan := runner.Run(ctx, scanArgs)
	report.ScanExitCode = scan.ExitCode
	if interrupted(ctx, scan) {
		addError(&report, "interrupted", context.Canceled)
		return report, ExitInterrupted
	}
	if scan.Err != nil {
		addError(&report, "scan_start_failed", scan.Err)
		return report, ExitFailure
	}

	envelope, err := decodeEnvelope[ScanOutcome](scan.Stdout, "scan")
	if err != nil {
		addError(&report, "invalid_scan_json", err)
		return report, ExitFailure
	}
	report.ScanResults = append(report.ScanResults, envelope.Results...)
	readyResults := make([]ScanOutcome, 0, len(envelope.Results))
	seenSnapshots := make(map[string]struct{}, len(envelope.Results))
	for _, item := range envelope.Results {
		switch item.Status {
		case "ready":
			if item.SnapshotID == "" {
				addError(&report, "invalid_scan_result", errors.New("ready scan result has no snapshot_id"))
				continue
			}
			if item.Directory == "" {
				addError(&report, "invalid_scan_result", errors.New("ready scan result has no directory"))
				continue
			}
			key := item.Directory + "\x00" + item.SnapshotID
			if _, exists := seenSnapshots[key]; exists {
				addError(&report, "invalid_scan_result", fmt.Errorf("duplicate target/snapshot pair %q", item.SnapshotID))
				continue
			}
			seenSnapshots[key] = struct{}{}
			readyResults = append(readyResults, item)
			report.Summary.Ready++
		case "clean":
			report.Summary.Clean++
		case "findings":
			report.Summary.Findings++
		case "failed", "partial":
			report.Summary.ScanFailed++
		default:
			addError(&report, "invalid_scan_result", fmt.Errorf("unsupported scan status %q", item.Status))
		}
	}

	if scan.ExitCode != ExitOK && scan.ExitCode != ExitFailure && scan.ExitCode != ExitFindings && scan.ExitCode != ExitPartial {
		appendEnvelopeErrors(&report, envelope.Errors)
		if len(report.Errors) == 0 {
			addError(&report, "scan_failed", fmt.Errorf("scan exited with status %d", scan.ExitCode))
		}
		return report, scan.ExitCode
	}
	if (scan.ExitCode == ExitFailure || scan.ExitCode == ExitPartial || report.Summary.ScanFailed > 0 || len(report.Errors) > 0) && options.FailurePolicy == FailureStop {
		report.Summary.NotAttempted = report.Summary.Ready
		appendEnvelopeErrors(&report, envelope.Errors)
		return report, ExitFailure
	}

	stop := false
	for _, item := range readyResults {
		if stop {
			report.Summary.NotAttempted++
			continue
		}
		if ctx.Err() != nil {
			addError(&report, "interrupted", ctx.Err())
			return report, ExitInterrupted
		}
		invocation := runner.Run(ctx, withConfig(options.ConfigPath, "update", "--yes", "--json", "--directory", item.Directory, "--snapshot", item.SnapshotID))
		result := Result{Project: item.Project, Directory: item.Directory, SnapshotID: item.SnapshotID, Status: "failed", ExitCode: invocation.ExitCode}
		if interrupted(ctx, invocation) {
			result.Status = "cancelled"
			report.Results = append(report.Results, result)
			addError(&report, "interrupted", context.Canceled)
			return report, ExitInterrupted
		}
		if invocation.Err != nil {
			addError(&report, "update_start_failed", fmt.Errorf("snapshot %s: %w", item.SnapshotID, invocation.Err))
		} else if updateErr := validateUpdate(invocation.Stdout, item.SnapshotID, invocation.ExitCode); updateErr != nil {
			addError(&report, "invalid_update_result", updateErr)
		} else if invocation.ExitCode == ExitOK {
			result.Status = "updated"
			report.Summary.Updated++
		}
		if result.Status != "updated" {
			report.Summary.Failed++
			stop = options.FailurePolicy == FailureStop
		}
		report.Results = append(report.Results, result)
	}

	appendEnvelopeErrors(&report, envelope.Errors)
	if scan.ExitCode == ExitFailure || scan.ExitCode == ExitPartial || report.Summary.ScanFailed > 0 || report.Summary.Failed > 0 || len(report.Errors) > 0 {
		return report, ExitFailure
	}
	if scan.ExitCode == ExitFindings {
		return report, ExitFindings
	}
	return report, ExitOK
}

func validateOptions(options Options) error {
	if options.FailurePolicy != FailureContinue && options.FailurePolicy != FailureStop {
		return fmt.Errorf("failure policy must be %q or %q", FailureContinue, FailureStop)
	}
	if options.FindingsPolicy != FindingsReport && options.FindingsPolicy != FindingsFail {
		return fmt.Errorf("findings policy must be %q or %q", FindingsReport, FindingsFail)
	}
	return nil
}

func withConfig(path string, args ...string) []string {
	if path == "" {
		return append([]string(nil), args...)
	}
	return append([]string{"--config", path}, args...)
}

func decodeEnvelope[T any](data []byte, command string) (commandEnvelope[T], error) {
	var envelope commandEnvelope[T]
	if err := json.Unmarshal(data, &envelope); err != nil {
		return envelope, fmt.Errorf("decode %s JSON: %w", command, err)
	}
	if envelope.Format != 1 || envelope.Command != command || envelope.Results == nil || envelope.Errors == nil {
		return envelope, fmt.Errorf("invalid %s envelope", command)
	}
	return envelope, nil
}

func validateUpdate(data []byte, snapshotID string, exitCode int) error {
	envelope, err := decodeEnvelope[updateResult](data, "update")
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", snapshotID, err)
	}
	if exitCode != ExitOK {
		return nil
	}
	if len(envelope.Results) != 1 || envelope.Results[0].SnapshotID != snapshotID || envelope.Results[0].Status != "updated" {
		return fmt.Errorf("snapshot %s: successful update returned an inconsistent result", snapshotID)
	}
	return nil
}

func interrupted(ctx context.Context, invocation Invocation) bool {
	return ctx.Err() != nil || invocation.ExitCode == ExitInterrupted
}

func appendEnvelopeErrors(report *Report, envelopeErrors []Error) {
	for _, item := range envelopeErrors {
		if item.Code == "" {
			item.Code = "scan_failed"
		}
		report.Errors = append(report.Errors, item)
	}
}

func addError(report *Report, code string, err error) {
	report.Errors = append(report.Errors, Error{Code: code, Message: err.Error()})
}
