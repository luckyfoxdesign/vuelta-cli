package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/projectstate"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestResolveScanTargetsNeverImplicitlySelectsAll(t *testing.T) {
	project := t.TempDir()
	outside := t.TempDir()
	cfg := config.Config{Workspaces: []config.Workspace{{Name: "api", Path: project}}}
	_, err := resolveScanTargets(cfg, scanOptions{}, func() (string, error) { return outside, nil })
	if err == nil {
		t.Fatal("unregistered cwd unexpectedly resolved")
	}
	for _, hint := range []string{"scan --directory .", "project add .", "scan --all"} {
		if !strings.Contains(err.Error(), hint) {
			t.Fatalf("error %q does not contain %q", err, hint)
		}
	}
	if len(cfg.Workspaces) != 1 {
		t.Fatalf("resolver mutated config: %#v", cfg.Workspaces)
	}
}

func TestResolveScanTargetsExplicitAll(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	cfg := config.Config{Workspaces: []config.Workspace{{Name: "api", Path: first}, {Name: "web", Path: second}}}
	targets, err := resolveScanTargets(cfg, scanOptions{all: true}, os.Getwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].name != "api" || targets[1].name != "web" {
		t.Fatalf("targets = %#v", targets)
	}
}

func TestParseScanOptionsRejectsConflictingSelectorsAndKeepsJSON(t *testing.T) {
	options, _, err := parseScanOptions([]string{"--json", "--project", "api", "--all"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v", err)
	}
	if !options.jsonOutput {
		t.Fatal("JSON intent was lost on parse failure")
	}
}

func TestParseScanOptionsVerbose(t *testing.T) {
	options, _, err := parseScanOptions([]string{"--verbose", "--only", "vulnerabilities"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.verbose {
		t.Fatal("--verbose was not preserved")
	}
}

func TestParseScanOptionsTimeoutDefaultOverrideAndValidation(t *testing.T) {
	options, _, err := parseScanOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.timeout != defaultProjectScanTimeout {
		t.Fatalf("default timeout = %s, want %s", options.timeout, defaultProjectScanTimeout)
	}

	options, _, err = parseScanOptions([]string{"--timeout", "10m"})
	if err != nil {
		t.Fatal(err)
	}
	if options.timeout != 10*time.Minute {
		t.Fatalf("override timeout = %s", options.timeout)
	}
	if options, _, err = parseScanOptions([]string{"--timeout", "1h"}); err != nil || options.timeout != maxProjectScanTimeout {
		t.Fatalf("maximum timeout = %s, error = %v", options.timeout, err)
	}

	for _, args := range [][]string{
		{"--timeout"},
		{"--timeout", "invalid"},
		{"--timeout", "0"},
		{"--timeout", "-1s"},
		{"--timeout", "1h1s"},
		{"--timeout", "5m", "--timeout=10m"},
	} {
		if _, _, err := parseScanOptions(args); err == nil {
			t.Fatalf("parse %v unexpectedly succeeded", args)
		}
	}
}

func TestRunScanTargetsStopsAfterInvocationCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	results := runScanTargets(ctx, []scanTarget{{name: "first"}, {name: "second"}}, scanOptions{
		all: true, timeout: time.Minute,
	}, func(ctx context.Context, target scanTarget, options scanOptions) scanResult {
		calls++
		options.stageTracker.set(stageVulnerability)
		cancel()
		<-ctx.Done()
		return scanResult{Project: target.name, Status: "failed", Timeout: options.timeout.String()}
	})
	if calls != 1 || len(results) != 1 {
		t.Fatalf("cancelled invocation calls/results = %d/%d", calls, len(results))
	}
}

func TestScanExitPriorityPrefersFailedResultOverFindings(t *testing.T) {
	err := scanResultError(scanSummary{Failed: 1, Vulnerabilities: 3}, "vulnerabilities", false)
	var coded commandError
	if !errors.As(err, &coded) || coded.code != exitFailure {
		t.Fatalf("error = %#v, want exit %d", err, exitFailure)
	}
	err = scanResultError(scanSummary{Vulnerabilities: 3}, "vulnerabilities", false)
	if !errors.As(err, &coded) || coded.code != exitFindings {
		t.Fatalf("error = %#v, want exit %d", err, exitFindings)
	}
}

func TestScanExitCodeDistinguishesMixedResultsFromTotalFailure(t *testing.T) {
	var coded commandError
	if err := scanResultError(scanSummary{Failed: 1, Succeeded: 1}, "", false); !errors.As(err, &coded) || coded.code != exitPartial {
		t.Fatalf("mixed result error = %#v, want exit %d", err, exitPartial)
	}
	if err := scanResultError(scanSummary{Partial: 1}, "", false); !errors.As(err, &coded) || coded.code != exitPartial {
		t.Fatalf("partial result error = %#v, want exit %d", err, exitPartial)
	}
	if err := scanResultError(scanSummary{Failed: 2}, "", false); !errors.As(err, &coded) || coded.code != exitFailure {
		t.Fatalf("total failure error = %#v, want exit %d", err, exitFailure)
	}
	if err := scanResultError(scanSummary{Succeeded: 2}, "", false); err != nil {
		t.Fatalf("clean scan error = %v", err)
	}
}

func TestScanExitRequireImageScanGatesOnTierFourSkip(t *testing.T) {
	summary := scanSummary{Succeeded: 1, ImageScanSkipped: 1}
	if err := scanResultError(summary, "", false); err != nil {
		t.Fatalf("without --require-image-scan a tier-4 skip must not fail the scan: %v", err)
	}
	var coded commandError
	if err := scanResultError(summary, "", true); !errors.As(err, &coded) || coded.code != exitImageScanRequired {
		t.Fatalf("error = %#v, want exit %d", err, exitImageScanRequired)
	}
	if err := scanResultError(scanSummary{Succeeded: 1}, "", true); err != nil {
		t.Fatalf("--require-image-scan must not fail a scan with no tier-4 skips: %v", err)
	}
}

func TestBuildImageScanRecordsSurfacesBaseImageDriftAcrossScans(t *testing.T) {
	root := t.TempDir()
	first, warnings := buildImageScanRecords(root, []vulnscan.ImageResolution{
		{Reference: "node:20-alpine", ResolvedDigest: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64", Tier: vulnscan.TierBaseImageTag},
	}, nil)
	if len(warnings) != 0 {
		t.Fatalf("first scan has no prior state to drift against: %v", warnings)
	}
	target, err := projectstate.FromCanonical(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistImageScanState(target, first); err != nil {
		t.Fatal(err)
	}

	second, warnings := buildImageScanRecords(root, []vulnscan.ImageResolution{
		{Reference: "node:20-alpine", ResolvedDigest: "sha256:" + strings.Repeat("b", 64), Platform: "linux/amd64", Tier: vulnscan.TierBaseImageTag},
	}, nil)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "drift") {
		t.Fatalf("second scan must surface base image drift: %#v", warnings)
	}
	if second[0].Drift == nil || second[0].Drift.PreviousDigest != "sha256:"+strings.Repeat("a", 64) || second[0].Drift.CurrentDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("drift record = %#v", second[0].Drift)
	}
}

func TestWriteScanPreflightShowsSingleAndMultipleDetectedStacks(t *testing.T) {
	tests := []struct {
		name     string
		detected []string
		want     string
	}{
		{name: "single", detected: []string{"node"}, want: "Detected: node\n"},
		{name: "multiple", detected: []string{"docker", "node"}, want: "Detected: docker, node\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := config.Workspace{Name: "landing", Path: "/projects/landing", Stack: config.StackNode, PackageManager: "npm"}
			var output strings.Builder
			writeScanPreflight(
				&output,
				scanOptions{},
				config.Config{Workspaces: []config.Workspace{workspace}},
				scanConfigSelection{
					Path:           "/projects/landing/.vuelta.yaml",
					Scope:          "project",
					Status:         "reused",
					DriftWarning:   "persisted stack drift detail",
					DetectedStacks: test.detected,
				},
				[]scanTarget{{workspace: &workspace, name: "landing", path: "/projects/landing"}},
			)
			text := output.String()
			for _, wanted := range []string{
				"Project:  landing (/projects/landing)\n",
				"Config:   .vuelta.yaml (reused)\n",
				test.want,
				"Selected: node/npm\n",
			} {
				if !strings.Contains(text, wanted) {
					t.Fatalf("preflight output %q does not contain %q", text, wanted)
				}
			}
			if strings.Contains(text, "persisted stack drift detail") || strings.ContainsAny(text, "\x1b\r") {
				t.Fatalf("preflight duplicated drift warning or emitted terminal controls: %q", text)
			}
		})
	}
}

func TestWriteScanPreflightKeepsJSONOutputClean(t *testing.T) {
	workspace := config.Workspace{Name: "landing", Path: "/projects/landing", Stack: config.StackNode, PackageManager: "npm"}
	var output strings.Builder
	writeScanPreflight(
		&output,
		scanOptions{jsonOutput: true},
		config.Config{Workspaces: []config.Workspace{workspace}},
		scanConfigSelection{Path: "/projects/landing/.vuelta.yaml", Scope: "project", Status: "reused", DetectedStacks: []string{"node"}},
		[]scanTarget{{workspace: &workspace, name: "landing", path: "/projects/landing"}},
	)
	if output.Len() != 0 {
		t.Fatalf("--json preflight output = %q, want empty", output.String())
	}
}

func TestExecuteScanWritesPlainPreflightBeforeFirstPhase(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr := captureScanOutput(t, func() {
		_ = executeScan([]string{"--directory", project, "--internal-no-color", "--internal-no-input"})
	})
	for _, wanted := range []string{
		"Project:  " + filepath.Base(project) + " (" + project + ")\n",
		"Config:   .vuelta.yaml (created)\n",
		"Detected: node\n",
		"Selected: node/npm\n",
	} {
		if !strings.Contains(stderr, wanted) {
			t.Fatalf("scan stderr %q does not contain preflight line %q", stderr, wanted)
		}
	}
	headerIndex := strings.Index(stderr, "Project:")
	phaseIndex := strings.Index(stderr, "Checking GitHub security alerts...")
	if headerIndex < 0 || phaseIndex < 0 || headerIndex >= phaseIndex {
		t.Fatalf("preflight must precede the first scan phase: %q", stderr)
	}
	if strings.ContainsAny(stderr, "\x1b\r") {
		t.Fatalf("non-tty scan output contains terminal controls: %q", stderr)
	}
}

func TestScanPhaseMessagePrefixesAllTargets(t *testing.T) {
	got := scanPhaseMessage(
		scanOptions{all: true, progressIndex: 2, progressTotal: 5},
		scanTarget{name: "landing", path: "/projects/landing"},
		"Scanning npm packages for updates...",
	)
	want := "[2/5 landing] Scanning npm packages for updates..."
	if got != want {
		t.Fatalf("phase message = %q, want %q", got, want)
	}
}

func TestScanStepProgressFormatsCountsAndPreservesProjectPrefix(t *testing.T) {
	var output strings.Builder
	progress := newScanProgress(false, &output)
	options := scanOptions{all: true, progressIndex: 2, progressTotal: 5}
	target := scanTarget{name: "landing", path: "/projects/landing"}
	update := scanStepProgress(progress, options, target, "Images")

	update("Preparing scan input", 0, 0)
	update("python:3.12 (linux/amd64)", 2, 3)

	want := "" +
		"[2/5 landing] Images: Preparing scan input\n" +
		"[2/5 landing] Images 2/3: python:3.12 (linux/amd64)\n"
	if output.String() != want {
		t.Fatalf("step progress = %q, want %q", output.String(), want)
	}
}

func TestScannerPlatformMismatchUsesSafePublicFailureContract(t *testing.T) {
	result := failedScanResult(
		scanResult{},
		stageVulnerability,
		"vulnerability_scan_failed",
		&vulnscan.ScannerPlatformError{},
		"",
	)
	if result.Error == nil ||
		result.Error.Code != "scanner_platform_mismatch" ||
		result.Error.Category != "scanner_platform_mismatch" ||
		result.Error.Message != "scanner image is incompatible with the Docker runtime platform" ||
		!strings.Contains(result.Error.Hint, "scanner image") ||
		!strings.Contains(result.Error.Hint, "Docker runtime platform") ||
		result.Error.ExitCode != nil ||
		result.Error.StderrTail != "" {
		t.Fatalf("platform failure = %#v", result.Error)
	}
	if !isPartialCapabilityFailure(result.Error) {
		t.Fatalf("platform failure is not a partial-capability category: %#v", result.Error)
	}
	for _, capability := range result.Capabilities {
		if capability.Name == "trivy_database" {
			t.Fatalf("platform mismatch changed database capability: %#v", result.Capabilities)
		}
	}
}

func TestHumanScanOutputSkipsWarningsAlreadyShownAtCommandLevel(t *testing.T) {
	result := scanResult{
		Directory: "/tmp/project", Status: "clean",
		Warnings: []string{onboardingChangedWarning, "only shown per-project"},
	}
	_, stderr := captureScanOutput(t, func() {
		writeHumanScanResults([]scanResult{result}, "", true, []string{onboardingChangedWarning})
	})
	if strings.Contains(stderr, "Warning: "+onboardingChangedWarning) {
		t.Fatalf("warning already shown at command level was printed again: %q", stderr)
	}
	if !strings.Contains(stderr, "Warning: only shown per-project") {
		t.Fatalf("unique per-project warning is missing: %q", stderr)
	}
}

func TestHumanScanTimeoutIdentifiesCodeStageAndDuration(t *testing.T) {
	result := projectScanTimeoutResult(scanResult{
		Project: "api", Directory: "/tmp/project", Status: "clean",
		Stages: []scanStageResult{{Name: stagePreflight, Status: string(stageSucceeded)}},
	}, stageVulnerability, 10*time.Minute, "")
	stdout, stderr := captureScanOutput(t, func() {
		writeHumanScanResults([]scanResult{result}, "", false, nil)
	})
	if !strings.Contains(stdout, "Project timeout: 10m0s") {
		t.Fatalf("timeout stdout = %q", stdout)
	}
	for _, wanted := range []string{"scan_timeout", stageVulnerability, "10m0s"} {
		if !strings.Contains(stderr, wanted) {
			t.Fatalf("timeout stderr %q does not contain %q", stderr, wanted)
		}
	}
}

func TestProjectScanReportBoundsVulnerabilityList(t *testing.T) {
	findings := make([]string, 150)
	for index := range findings {
		findings[index] = fmt.Sprintf("CVE-%03d", index)
	}
	data, err := buildProjectScanReport(scanResult{
		Project: "api", Directory: "/projects/api", Status: "findings", Vulnerabilities: findings,
	}, scanOptions{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	if !strings.Contains(report, "full count: 150") || strings.Contains(report, "CVE-149") {
		t.Fatalf("vulnerability truncation missing:\n%s", report)
	}
}

func captureScanOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previousStdout, previousStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	fn()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = previousStdout, previousStderr
	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatal(err)
	}
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	return string(stdout), string(stderr)
}
