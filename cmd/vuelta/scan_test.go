package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/projectstate"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestResolveScanTargetsDoesNotWalkToContainingRegisteredProject(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "services", "api")
	working := filepath.Join(nested, "internal")
	for _, path := range []string{nested, working} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{Workspaces: []config.Workspace{
		{Name: "root", Path: root},
		{Name: "api", Path: nested},
	}}
	if _, err := resolveScanTargets(cfg, scanOptions{}, func() (string, error) { return working, nil }); err == nil {
		t.Fatal("nested current directory unexpectedly selected a parent project")
	}
	targets, err := resolveScanTargets(cfg, scanOptions{directory: working}, os.Getwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].path != working || targets[0].origin != updatesnapshot.OriginAdhoc {
		t.Fatalf("exact nested target = %#v", targets)
	}
}

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

func TestResolveScanTargetsExplicitAdhocDirectory(t *testing.T) {
	directory := t.TempDir()
	targets, err := resolveScanTargets(config.Config{}, scanOptions{directory: directory}, os.Getwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].origin != updatesnapshot.OriginAdhoc || targets[0].path != directory || targets[0].workspace != nil {
		t.Fatalf("targets = %#v", targets)
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

func TestMachineScanTargetOnboardingCreatesLocalPolicyAndExactIgnoreOnce(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{
		"package.json":      "{}\n",
		"package-lock.json": "{}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := config.Workspace{
		Name: "api", Path: root, Stack: config.StackNode, PackageManager: "npm",
		Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
		AllowedChangedPaths: []string{"package.json", "package-lock.json"},
	}
	targets := onboardMachineScanTargets([]scanTarget{{
		workspace: &workspace, name: "api", path: root, origin: updatesnapshot.OriginWorkspace,
	}})
	if len(targets) != 1 || targets[0].err != nil || !targets[0].onboardingChanged {
		t.Fatalf("first onboarding = %#v", targets)
	}
	for _, path := range []string{filepath.Join(root, projectConfigName), filepath.Join(root, ".gitignore")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("missing onboarding file %s: %v", path, err)
		}
	}
	repeated := onboardMachineScanTargets([]scanTarget{{
		workspace: &workspace, name: "api", path: root, origin: updatesnapshot.OriginWorkspace,
	}})
	if repeated[0].err != nil || repeated[0].onboardingChanged {
		t.Fatalf("repeated onboarding = %#v", repeated)
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

func TestParseScanOptionsOnlyModes(t *testing.T) {
	for _, test := range []struct {
		args    []string
		only    string
		wantErr bool
	}{
		{args: []string{"--only", "vulnerabilities"}, only: "vulnerabilities"},
		{args: []string{"--only", "packages"}, only: "packages"},
		{args: []string{"--only", "other"}, wantErr: true},
	} {
		options, _, err := parseScanOptions(test.args)
		if (err != nil) != test.wantErr {
			t.Fatalf("parse %v error = %v, wantErr %t", test.args, err, test.wantErr)
		}
		if !test.wantErr && options.only != test.only {
			t.Fatalf("parse %v = %#v", test.args, options)
		}
	}
}

func TestParseScanOptionsVerbose(t *testing.T) {
	options, _, err := parseScanOptions([]string{"--verbose", "--only", "packages"})
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

func TestRunScanTargetsUsesFreshDeadlineAndContinuesAfterProjectTimeout(t *testing.T) {
	targets := []scanTarget{
		{name: "slow", path: "/projects/slow"},
		{name: "fast", path: "/projects/fast"},
	}
	var calls int
	results := runScanTargets(context.Background(), targets, scanOptions{
		all: true, timeout: 20 * time.Millisecond,
	}, func(ctx context.Context, target scanTarget, options scanOptions) scanResult {
		calls++
		if target.name == "slow" {
			options.stageTracker.set(stageCandidate)
			<-ctx.Done()
			return scanResult{
				Project: target.name, Directory: target.path, Status: "ready",
				Timeout: options.timeout.String(), SnapshotID: "new-snapshot",
				Stages: []scanStageResult{
					{Name: stagePreflight, Status: string(stageSucceeded)},
					{Name: stageVulnerability, Status: string(stageSucceeded)},
					{Name: stageAlerts, Status: string(stageSucceeded)},
				},
				Vulnerabilities: []string{"CVE-1"},
			}
		}
		if ctx.Err() != nil {
			t.Fatal("second project inherited the first project's expired context")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 {
			t.Fatal("second project did not receive a fresh deadline")
		}
		return scanResult{
			Project: target.name, Directory: target.path, Status: "clean",
			Timeout: options.timeout.String(),
		}
	})
	if calls != 2 || len(results) != 2 {
		t.Fatalf("calls/results = %d/%d", calls, len(results))
	}
	timedOut := results[0]
	if timedOut.Error == nil || timedOut.Error.Code != "scan_timeout" ||
		timedOut.Error.Stage != stageCandidate || timedOut.Error.Category != "timeout" {
		t.Fatalf("timeout error = %#v", timedOut.Error)
	}
	if timedOut.Timeout != "20ms" || timedOut.SnapshotID != "" ||
		timedOut.PackageUpdates == nil || timedOut.PackageUpdates.Reason != "scan_timeout" {
		t.Fatalf("timeout result = %#v", timedOut)
	}
	data, err := json.Marshal(timedOut)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{`"timeout":"20ms"`, `"code":"scan_timeout"`, `"stage":"candidate"`} {
		if !strings.Contains(string(data), wanted) {
			t.Fatalf("timeout JSON %s does not contain %s", data, wanted)
		}
	}
	statuses := make(map[string]string)
	for _, stage := range timedOut.Stages {
		statuses[stage.Name] = stage.Status
	}
	if statuses[stageVulnerability] != string(stageSucceeded) ||
		statuses[stageCandidate] != string(stageFailed) ||
		statuses[stageReleaseAge] != string(stageNotStarted) ||
		statuses[stageSnapshot] != string(stageNotStarted) {
		t.Fatalf("timeout stages = %#v", timedOut.Stages)
	}
	if results[1].Status != "clean" {
		t.Fatalf("second result = %#v", results[1])
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

func TestEffectiveMinReleaseAge(t *testing.T) {
	for _, test := range []struct {
		value      string
		configured int
		policy     int
		want       time.Duration
	}{
		{configured: 7, policy: 14, want: 14 * 24 * time.Hour},
		{value: "14d", want: 14 * 24 * time.Hour},
		{value: "336h", want: 14 * 24 * time.Hour},
	} {
		got, err := effectiveMinReleaseAge(test.value, test.configured, test.policy)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("effective age for %q = %s, want %s", test.value, got, test.want)
		}
	}
	for _, value := range []string{"0", "12h", "7d"} {
		if _, err := effectiveMinReleaseAge(value, 14, 0); err == nil {
			t.Fatalf("unsafe effective age %q was accepted", value)
		}
	}
}

func TestReleaseAgeStageHasExplicitSemantics(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := config.Workspace{
		Name: "example", Path: root, Stack: config.StackNode, PackageManager: "npm",
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
	}
	target := scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace}
	for _, testCase := range []struct {
		name, want string
		verified   bool
		err        error
	}{
		{name: "verified", verified: true, want: string(stageVerified)},
		{name: "unverified", want: string(stageUnverified)},
		{name: "failed", err: errors.New("scanner failed"), want: string(stageFailed)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			runners := scanStageRunners{
				vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
					return nil, nil, nil, "trivy", false, nil
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
					return nil, false, nil
				},
				packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
					if testCase.err != nil {
						return nil, "npm", false, testCase.err
					}
					return []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Current: "1.0.0", Target: "2.0.0"}}, "npm", testCase.verified, nil
				},
			}
			result := scanOneTargetWith(context.Background(), config.Config{}, target, scanOptions{only: "packages"}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 7*24*time.Hour, runners)
			got := ""
			for _, stage := range result.Stages {
				if stage.Name == stageReleaseAge {
					got = stage.Status
				}
			}
			if got != testCase.want {
				t.Fatalf("release-age status = %q, want %q; result=%#v", got, testCase.want, result)
			}
			if testCase.want == string(stageUnverified) && len(result.Warnings) == 0 {
				t.Fatal("unverified release age was not surfaced as a warning")
			}
		})
	}
}

func TestNoOpOnlyPackageScanIsCleanAndPublishesNoSnapshot(t *testing.T) {
	root := t.TempDir()
	manifest := []byte(`{"name":"example","dependencies":{"canvg":"4.0.3"}}`)
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/canvg":{"version":"4.0.3"}}}`)
	if err := os.WriteFile(filepath.Join(root, "package.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), lock, 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := config.Workspace{
		Name: "example", Path: root, Stack: config.StackNode, PackageManager: "npm",
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationReady},
	}
	runners := scanStageRunners{
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return []updatesnapshot.Candidate{{
				Kind: "npm", Name: "canvg", Current: "4.0.3", Target: "4.0.3", Ownership: "direct",
			}}, "npm", true, nil
		},
	}
	result := scanOneTargetWith(
		context.Background(), config.Config{},
		scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace},
		scanOptions{only: "packages"}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners,
	)
	if result.Status != "clean" || len(result.Candidates) != 0 || result.SnapshotID != "" {
		t.Fatalf("no-op scan = %#v", result)
	}
	if got, err := os.ReadFile(filepath.Join(root, "package.json")); err != nil || string(got) != string(manifest) {
		t.Fatalf("package.json changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "package-lock.json")); err != nil || string(got) != string(lock) {
		t.Fatalf("package-lock.json changed: %q, %v", got, err)
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

func TestScanStagesContinueAfterIndependentFailures(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{
		"package.json":      `{"name":"example"}`,
		"package-lock.json": `{"lockfileVersion":3}`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := config.Workspace{
		Name: "example", Path: root, Stack: config.StackNode, PackageManager: "npm",
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
	}
	target := scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace}
	policyIdentity := updatesnapshot.PolicyIdentity{Path: updatesnapshot.PolicyNone, Hash: updatesnapshot.PolicyNone}

	tests := []struct {
		name             string
		dependencySource string
		vulnerabilityErr error
		alertErr         error
		packageErr       error
		wantStage        string
	}{
		{name: "vulnerability failure preserves packages", dependencySource: "trivy", vulnerabilityErr: errors.New("trivy unavailable"), wantStage: stageVulnerability},
		{name: "optional alerts failure preserves packages", dependencySource: "github-dependabot", alertErr: errors.New("GitHub API unavailable"), wantStage: stageAlerts},
		{name: "package failure preserves vulnerabilities", dependencySource: "trivy", packageErr: errors.New("unsupported manager"), wantStage: stageCandidate},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runners := scanStageRunners{
				vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
					if test.dependencySource == "github-dependabot" {
						return nil, nil, nil, "trivy-images", false, nil
					}
					return []vulnscan.Finding{{ID: "CVE-1"}}, nil, nil, "trivy", true, test.vulnerabilityErr
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
					if test.dependencySource != "github-dependabot" {
						return nil, false, nil
					}
					return []vulnscan.Finding{{ID: "GHSA-1"}}, true, test.alertErr
				},
				packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
					if test.packageErr != nil {
						return nil, "npm", false, test.packageErr
					}
					return []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Current: "1.0.0", Target: "2.0.0"}}, "npm", true, nil
				},
			}
			cfg := config.Config{VulnScan: config.VulnScanConfig{DependencySource: test.dependencySource}}
			result := scanOneTargetWith(context.Background(), cfg, target, scanOptions{}, config.LocalPackagePolicy{}, policyIdentity, 0, runners)
			if result.Status != "partial" {
				t.Fatalf("status = %q, want partial; result=%#v", result.Status, result)
			}
			if !hasFailedStage(result, test.wantStage) || len(result.Warnings) == 0 {
				t.Fatalf("missing failed stage/warning: %#v", result)
			}
			if test.packageErr == nil && len(result.Candidates) != 1 {
				t.Fatalf("package result was lost: %#v", result.Candidates)
			}
			if test.packageErr != nil && len(result.Vulnerabilities) != 1 {
				t.Fatalf("vulnerability result was lost: %#v", result.Vulnerabilities)
			}
		})
	}
}

func TestCandidateDeadlinePreservesVulnerabilitiesAndNextScanSucceeds(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{
		"package.json":   `{"packageManager":"pnpm@11.8.0"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := config.Workspace{
		Name: "blocked-pnpm", Path: root, Stack: config.StackNode, PackageManager: "pnpm",
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
	}
	target := scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace}
	packageCalls := 0
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return []vulnscan.Finding{{ID: "CVE-PRESERVED"}}, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(ctx context.Context, _ config.Config, _ scanTarget, _ scanOptions, _ config.LocalPackagePolicy, _ time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			packageCalls++
			if packageCalls == 1 {
				<-ctx.Done()
				return nil, "pnpm", false, ctx.Err()
			}
			return []updatesnapshot.Candidate{{
				Kind: "pnpm", Name: "example", Current: "1.0.0", Target: "2.0.0",
			}}, "pnpm", true, nil
		},
		candidateTimeout: 20 * time.Millisecond,
	}

	first := scanOneTargetWith(
		context.Background(), config.Config{}, target, scanOptions{},
		config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners,
	)
	if first.Status != "partial" || len(first.Vulnerabilities) != 1 ||
		first.Vulnerabilities[0] != "CVE-PRESERVED" || !hasFailedStage(first, stageCandidate) {
		t.Fatalf("timed-out result lost completed stages: %#v", first)
	}
	if first.Error == nil || first.Error.Code != "package_scan_timeout" ||
		first.Error.Stage != stageCandidate || first.Error.Category != "timeout" ||
		!strings.Contains(first.Error.Message, "pnpm") ||
		!strings.Contains(first.Error.Message, "20ms") {
		t.Fatalf("candidate timeout contract = %#v", first.Error)
	}
	if first.PackageUpdates == nil || first.PackageUpdates.Reason != "package_scan_timeout" {
		t.Fatalf("package availability = %#v", first.PackageUpdates)
	}

	second := scanOneTargetWith(
		context.Background(), config.Config{}, target, scanOptions{},
		config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners,
	)
	if hasFailedStage(second, stageCandidate) || len(second.Candidates) != 1 ||
		second.Candidates[0].Name != "example" {
		t.Fatalf("subsequent candidate scan did not recover: %#v", second)
	}
}

func TestManifestOnlyNPMScanPreservesReadOnlyFindingsAndNeverRunsMutationStages(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"demo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	target := scanTarget{path: root, origin: updatesnapshot.OriginAdhoc}
	vulnerabilityCalls := 0
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			vulnerabilityCalls++
			return []vulnscan.Finding{{ID: "CVE-READ-ONLY"}}, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			t.Fatal("manifest-only npm invoked package candidate scanning")
			return nil, "", false, nil
		},
		prepareToolchain: func(context.Context, config.Config, config.Workspace) (toolchain.Prepared, error) {
			t.Fatal("manifest-only npm prepared a lock-dependent toolchain")
			return toolchain.Prepared{}, nil
		},
	}
	var first scanResult
	for run := 0; run < 2; run++ {
		result := scanOneTargetWith(
			context.Background(),
			config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy"}},
			target,
			scanOptions{},
			config.LocalPackagePolicy{},
			updatesnapshot.PolicyIdentity{},
			0,
			runners,
		)
		if result.Status != "partial" || result.Error == nil || result.Error.Code != reasonLockfileMissing {
			t.Fatalf("run %d result = %#v", run+1, result)
		}
		if result.Stack != config.StackNode || result.PackageManager != "npm" {
			t.Fatalf("run %d detected ecosystem = %s/%s", run+1, result.Stack, result.PackageManager)
		}
		if len(result.Vulnerabilities) != 1 || result.Vulnerabilities[0] != "CVE-READ-ONLY" {
			t.Fatalf("run %d findings = %#v", run+1, result.Vulnerabilities)
		}
		if result.PackageUpdates == nil || result.PackageUpdates.Status != "unavailable" ||
			result.PackageUpdates.Reason != reasonLockfileMissing {
			t.Fatalf("run %d package updates = %#v", run+1, result.PackageUpdates)
		}
		if result.SnapshotID != "" || !hasFailedStage(result, stageCandidate) {
			t.Fatalf("run %d snapshot/stages = %q %#v", run+1, result.SnapshotID, result.Stages)
		}
		if run == 0 {
			first = result
		} else if !reflect.DeepEqual(first.Warnings, result.Warnings) {
			t.Fatalf("repeat warnings changed: %#v != %#v", first.Warnings, result.Warnings)
		}
	}
	if vulnerabilityCalls != 2 {
		t.Fatalf("vulnerability calls = %d", vulnerabilityCalls)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "package.json" {
		t.Fatalf("manifest-only scans changed the project: %#v", entries)
	}
}

func TestScanOneTargetWithNonTTYProgressStaysPlain(t *testing.T) {
	root := t.TempDir()
	workspace := config.Workspace{Name: "example", Path: root, Stack: config.StackNode, PackageManager: "npm"}
	target := scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace}
	policyIdentity := updatesnapshot.PolicyIdentity{Path: updatesnapshot.PolicyNone, Hash: updatesnapshot.PolicyNone}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Current: "1.0.0", Target: "2.0.0"}}, "npm", true, nil
		},
	}
	cfg := config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy"}}
	_, stderr := captureScanOutput(t, func() {
		scanOneTargetWith(context.Background(), cfg, target, scanOptions{}, config.LocalPackagePolicy{}, policyIdentity, 0, runners)
	})
	for _, wanted := range []string{
		"Scanning dependencies with trivy...\n",
		"Checking GitHub security alerts...\n",
		"Scanning npm packages for updates...\n",
	} {
		if !strings.Contains(stderr, wanted) {
			t.Fatalf("non-tty progress output missing %q: %q", wanted, stderr)
		}
	}
	for _, forbidden := range []string{"\r", "\x1b"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("non-tty progress output contains animation control characters: %q", stderr)
		}
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

func TestStandaloneRequirementsVulnerabilityOnlyRunsScanner(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := scanTarget{path: root, origin: updatesnapshot.OriginAdhoc}
	vulnerabilityCalled := false
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			vulnerabilityCalled = true
			return []vulnscan.Finding{{ID: "CVE-2026-0001"}}, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			t.Fatal("package scanner was called for --only vulnerabilities")
			return nil, "", false, nil
		},
	}
	result := scanOneTargetWith(context.Background(), config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "trivy",
	}}, target, scanOptions{only: "vulnerabilities"}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	if !vulnerabilityCalled || result.Status != config.VerificationScanOnly || len(result.Vulnerabilities) != 1 || result.Error != nil {
		t.Fatalf("result = %#v; vulnerabilityCalled=%t", result, vulnerabilityCalled)
	}
	if !containsString(result.InputCategories, string(scaninput.CategoryDependency)) || result.SnapshotID != "" || result.PackageUpdates == nil || result.PackageUpdates.Reason != "manifest_has_no_safe_mutation_contract" {
		t.Fatalf("input/snapshot result = %#v", result)
	}
}

func TestStandaloneRequirementsCombinedScanReturnsCandidatesWithoutSnapshot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return []vulnscan.Finding{{ID: "CVE-2026-0001"}}, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(_ context.Context, _ config.Config, _ scanTarget, options scanOptions, _ config.LocalPackagePolicy, _ time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			if options.packageDiagnostics != nil {
				*options.packageDiagnostics = append(*options.packageDiagnostics, updater.ScanDiagnostic{
					File: "requirements.txt", Line: 2, Code: "exact_pin_required",
					Severity: "info", Disposition: "unsupported",
					Message: "expected one exact pin",
				})
			}
			return []updatesnapshot.Candidate{{
				Kind: "requirements", Name: "flask", Current: "0.5", Target: "3.1.2",
				File: "requirements.txt", Line: 1, Disposition: "scanned",
			}}, "requirements", false, nil
		},
	}
	result := scanOneTargetWith(context.Background(), config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "trivy",
	}}, scanTarget{path: root, origin: updatesnapshot.OriginAdhoc}, scanOptions{}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 7*24*time.Hour, runners)
	if result.Status != config.VerificationScanOnly || result.Error != nil || result.PackageUpdates == nil || result.PackageUpdates.Reason != "manifest_has_no_safe_mutation_contract" {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Vulnerabilities) != 1 || len(result.Candidates) != 1 || len(result.Diagnostics) != 1 || result.SnapshotID != "" || hasFailedStage(result, stageCandidate) {
		t.Fatalf("vulnerability/snapshot result = %#v", result)
	}
	if result.Diagnostics[0].Severity != "info" || result.Diagnostics[0].Disposition != "unsupported" {
		t.Fatalf("diagnostic = %#v", result.Diagnostics[0])
	}
	if result.Candidates[0].File != "requirements.txt" || result.Candidates[0].Line != 1 ||
		result.Candidates[0].Disposition != "scanned" {
		t.Fatalf("candidate provenance = %#v", result.Candidates[0])
	}
	if !containsSubstring(result.Warnings, "no update snapshot") {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if !containsSubstring(result.Warnings, "release age could not be verified") {
		t.Fatalf("release-age warnings = %#v", result.Warnings)
	}
	if err := scanResultError(summarizeScan([]scanResult{result}), "", false); err != nil {
		t.Fatalf("scan-only findings returned failure exit: %v", err)
	}
}

func TestCandidateResultsSurvivePersistentTrivyDatabaseUnavailability(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	databaseAgeHours := 31
	databaseErr := &vulnscan.DatabaseAcquisitionError{
		Kind: vulnscan.FailureTransientTransport, Attempts: 3,
		History: []string{
			"attempt 1: transient_transport",
			"attempt 2: transient_transport",
			"attempt 3: transient_transport",
		},
		CacheStatus: "stale", DatabaseAgeHours: &databaseAgeHours,
		Err: errors.New("unexpected EOF"),
	}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy", true, databaseErr
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return []updatesnapshot.Candidate{{
				Kind: "requirements", Name: "flask", Current: "0.5", Target: "3.1.2",
				File: "requirements.txt", Line: 1, Disposition: "scanned",
			}}, "requirements", true, nil
		},
	}
	result := scanOneTargetWith(
		context.Background(),
		config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy"}},
		scanTarget{path: root, origin: updatesnapshot.OriginAdhoc},
		scanOptions{},
		config.LocalPackagePolicy{},
		updatesnapshot.PolicyIdentity{},
		0,
		runners,
	)
	if result.Status != "partial" || len(result.Candidates) != 1 || !hasFailedStage(result, stageVulnerability) {
		t.Fatalf("partial candidate result = %#v", result)
	}
	if result.Error == nil ||
		result.Error.Code != "trivy_database_transient_transport" ||
		result.Error.Category != "trivy_database_transient_transport" ||
		result.Error.CacheStatus != "stale" ||
		result.Error.DatabaseAgeHours == nil ||
		*result.Error.DatabaseAgeHours != databaseAgeHours ||
		!reflect.DeepEqual(result.Error.RetryHistory, databaseErr.History) {
		t.Fatalf("structured database error = %#v", result.Error)
	}
	var databaseCapability *scanCapability
	for index := range result.Capabilities {
		if result.Capabilities[index].Name == "trivy_database" {
			databaseCapability = &result.Capabilities[index]
		}
	}
	if databaseCapability == nil ||
		databaseCapability.Status != "stale" ||
		databaseCapability.Reason != "trivy_database_transient_transport" ||
		databaseCapability.CacheStatus != "stale" ||
		databaseCapability.DatabaseAgeHours == nil ||
		*databaseCapability.DatabaseAgeHours != databaseAgeHours {
		t.Fatalf("database capability = %#v", result.Capabilities)
	}
	if !containsSubstring(result.Warnings, "retry_history=attempt 1: transient_transport") {
		t.Fatalf("retry history is absent from bounded warning: %#v", result.Warnings)
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

func TestStandaloneRequirementsPackagesOnlyIsScanOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			t.Fatal("vulnerability scanner was called for --only packages")
			return nil, nil, nil, "", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			t.Fatal("alerts scanner was called for --only packages")
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return []updatesnapshot.Candidate{{Kind: "requirements", Name: "flask", Current: "0.5", Target: "3.1.2"}}, "requirements", false, nil
		},
	}
	result := scanOneTargetWith(context.Background(), config.Config{}, scanTarget{
		path: root, origin: updatesnapshot.OriginAdhoc,
	}, scanOptions{only: "packages"}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	if result.Status != config.VerificationScanOnly || result.Error != nil || len(result.Candidates) != 1 || result.SnapshotID != "" {
		t.Fatalf("result = %#v", result)
	}
	if result.PackageUpdates == nil || result.PackageUpdates.Reason != "manifest_has_no_safe_mutation_contract" || hasFailedStage(result, stageCandidate) {
		t.Fatalf("diagnostics = %#v", result)
	}
}

func TestRegisteredScanOnlyRequirementsWorkspaceUsesDependencyContract(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := config.Workspace{
		Name: "legacy-python", Path: root, Stack: config.StackPython,
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
	}
	called := false
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			called = true
			return nil, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			t.Fatal("package scanner was called")
			return nil, "", false, nil
		},
	}
	result := scanOneTargetWith(context.Background(), config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "trivy",
	}}, scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace}, scanOptions{
		only: "vulnerabilities",
	}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	if !called || result.Status != config.VerificationScanOnly || result.Error != nil || !containsString(result.InputCategories, string(scaninput.CategoryDependency)) {
		t.Fatalf("result = %#v; called=%t", result, called)
	}
}

func TestDockerOnlyCandidateStageUsesDockerRegistry(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := config.Workspace{
		Name: "docker-only", Path: root, Stack: config.StackDocker,
		DockerImages: &config.DockerImagesSpec{
			Files:         []string{"Dockerfile"},
			RuntimeImages: []string{"scratch"},
		},
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
	}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: scanPackages,
	}
	result := scanOneTargetWith(
		context.Background(),
		config.Config{},
		scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace},
		scanOptions{},
		config.LocalPackagePolicy{},
		updatesnapshot.PolicyIdentity{},
		0,
		runners,
	)
	if result.Error != nil || result.Status == "partial" || result.Status == "failed" {
		t.Fatalf("docker-only result = %#v", result)
	}
	candidateSucceeded := false
	for _, stage := range result.Stages {
		if stage.Name == stageCandidate && stage.Status == string(stageSucceeded) {
			candidateSucceeded = true
		}
	}
	if !candidateSucceeded {
		t.Fatalf("candidate stage did not succeed: %#v", result.Stages)
	}
	dockerRegistryUsed := false
	for _, tool := range result.Tools {
		if tool.Name == "docker-registry" && tool.Status == "used" {
			dockerRegistryUsed = true
		}
	}
	if !dockerRegistryUsed {
		t.Fatalf("docker-registry tool was not used: %#v", result.Tools)
	}
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "unsupported ecosystem: docker/") {
			t.Fatalf("unsupported docker ecosystem warning leaked: %q", warning)
		}
	}
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDockerUnavailableStillRunsIndependentAlerts(t *testing.T) {
	root := t.TempDir()
	workspace := config.Workspace{
		Name: "example", Path: root, Stack: config.StackNode, PackageManager: "npm",
		Verification: config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
	}
	target := scanTarget{
		workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace,
		dockerErr: errors.New("approved Docker endpoint is unavailable"),
	}
	alertsCalled := false
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy-images", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			alertsCalled = true
			return []vulnscan.Finding{{ID: "GHSA-1"}}, true, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			t.Fatal("Docker-backed package runner was called")
			return nil, "npm", false, nil
		},
	}
	cfg := config.Config{VulnScan: config.VulnScanConfig{DependencySource: "github-dependabot"}}
	result := scanOneTargetWith(context.Background(), cfg, target, scanOptions{}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	if !alertsCalled || result.Status != "partial" || len(result.Vulnerabilities) != 1 || !hasFailedStage(result, stageCandidate) {
		t.Fatalf("result = %#v", result)
	}
	if result.PackageUpdates == nil || result.PackageUpdates.Status != "unavailable" ||
		result.PackageUpdates.Reason != "package_scan_failed" {
		t.Fatalf("package update capability = %#v", result.PackageUpdates)
	}
}

func TestFailedWorkspaceDoesNotStopSupportedWorkspace(t *testing.T) {
	root := t.TempDir()
	workspace := config.Workspace{Name: "supported", Path: root, Stack: config.StackNode, PackageManager: "npm"}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			t.Fatal("package stage was not requested")
			return nil, "", false, nil
		},
	}
	options := scanOptions{only: "vulnerabilities"}
	broken := scanOneTargetWith(context.Background(), config.Config{}, scanTarget{name: "broken", path: "/missing", origin: updatesnapshot.OriginWorkspace, err: errors.New("configured path is unavailable")}, options, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	supported := scanOneTargetWith(context.Background(), config.Config{}, scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace}, options, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	summary := summarizeScan([]scanResult{broken, supported})
	if broken.Status != "failed" || supported.Status != "clean" || summary.Failed != 1 || summary.Succeeded != 1 {
		t.Fatalf("broken=%#v supported=%#v summary=%#v", broken, supported, summary)
	}
	var coded commandError
	if err := scanResultError(summary, "", false); !errors.As(err, &coded) || coded.code != exitPartial {
		t.Fatalf("mixed workspace exit = %#v, want %d", err, exitPartial)
	}
}

func TestGitlessWorkspaceKeepsCandidatesAndReportsCapability(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := config.Workspace{
		Name: "gitless", Path: root, Stack: config.StackNode, PackageManager: "npm",
		Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
		AllowedChangedPaths: []string{"package.json", "package-lock.json"},
	}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Current: "1.0.0", Target: "2.0.0"}}, "npm", true, nil
		},
	}
	result := scanOneTargetWith(
		context.Background(), config.Config{}, scanTarget{workspace: &workspace, name: workspace.Name, path: root},
		scanOptions{only: "packages"}, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners,
	)
	if result.Status != config.VerificationScanOnly || len(result.Candidates) != 1 || result.Error != nil {
		t.Fatalf("gitless result = %#v", result)
	}
	if result.PackageUpdates == nil || result.PackageUpdates.Reason != "git_repository_not_found" {
		t.Fatalf("gitless package capability = %#v", result.PackageUpdates)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].Reason != "git_repository_not_found" {
		t.Fatalf("gitless capabilities = %#v", result.Capabilities)
	}
}

func TestToolchainBuildFailureIsPerWorkspaceAndActionable(t *testing.T) {
	brokenRoot := t.TempDir()
	supportedRoot := t.TempDir()
	for _, root := range []string{brokenRoot, supportedRoot} {
		if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"engines":{"node":"22.x"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	brokenWorkspace := config.Workspace{Name: "broken", Path: brokenRoot, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	supportedWorkspace := config.Workspace{Name: "supported", Path: supportedRoot, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
			return nil, nil, nil, "trivy", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
			return nil, false, nil
		},
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return nil, "npm", true, nil
		},
		prepareToolchain: func(_ context.Context, _ config.Config, workspace config.Workspace) (toolchain.Prepared, error) {
			if workspace.Name == "broken" {
				return toolchain.Prepared{}, &toolchain.BuildError{
					Kind:    toolchain.BuildFailureVersionUnavailable,
					Manager: "npm", Version: "99.0.0", ExitCode: 1,
				}
			}
			selection, err := toolchain.Select(workspace, config.Config{})
			if err != nil {
				return toolchain.Prepared{}, err
			}
			selection.Profile.Image = "sha256:" + strings.Repeat("a", 64)
			identity, err := toolchain.IdentityForResolvedProfile(selection.Profile, selection.Source, selection.Profile.Image)
			return toolchain.Prepared{Selection: selection, Identity: identity}, err
		},
	}
	options := scanOptions{only: "packages"}
	broken := scanOneTargetWith(context.Background(), config.Config{}, scanTarget{workspace: &brokenWorkspace, name: "broken", path: brokenRoot, origin: updatesnapshot.OriginWorkspace}, options, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	supported := scanOneTargetWith(context.Background(), config.Config{}, scanTarget{workspace: &supportedWorkspace, name: "supported", path: supportedRoot, origin: updatesnapshot.OriginWorkspace}, options, config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, 0, runners)
	if broken.Status != "partial" || broken.Error == nil ||
		broken.Error.Code != string(toolchain.BuildFailureVersionUnavailable) ||
		!strings.Contains(broken.Error.Hint, "override") {
		t.Fatalf("broken result = %#v", broken)
	}
	if broken.PackageUpdates == nil || broken.PackageUpdates.Status != "unavailable" ||
		broken.PackageUpdates.Reason != string(toolchain.BuildFailureVersionUnavailable) {
		t.Fatalf("broken package update capability = %#v", broken.PackageUpdates)
	}
	if supported.Status != "clean" || hasFailedStage(supported, stageCandidate) {
		t.Fatalf("supported result = %#v", supported)
	}
	if supported.PackageUpdates == nil || supported.PackageUpdates.Status != "available" {
		t.Fatalf("supported package update capability = %#v", supported.PackageUpdates)
	}
	if supported.Toolchain == nil || supported.Toolchain.Runtime != "22" ||
		supported.Toolchain.Source != toolchain.SourceDefault ||
		supported.Toolchain.RuntimeConstraintSource != ecosystem.RuntimeConstraintSourceProject ||
		supported.Toolchain.RuntimeConstraint != ">=22.0.0 <23.0.0" {
		t.Fatalf("supported toolchain result = %#v", supported.Toolchain)
	}
	encoded, err := json.Marshal(supported)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Toolchain *struct {
			RuntimeConstraint       string `json:"runtime_constraint"`
			RuntimeConstraintSource string `json:"runtime_constraint_source"`
			Runtime                 string `json:"runtime"`
			Source                  string `json:"source"`
		} `json:"toolchain"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Toolchain == nil ||
		decoded.Toolchain.RuntimeConstraint != ">=22.0.0 <23.0.0" ||
		decoded.Toolchain.RuntimeConstraintSource != "project" ||
		decoded.Toolchain.Runtime != "22" ||
		decoded.Toolchain.Source != toolchain.SourceDefault {
		t.Fatalf("structured scan toolchain = %#v", decoded.Toolchain)
	}
}

func TestPNPMOutputFailuresHaveDistinctStableContracts(t *testing.T) {
	tests := []struct {
		name string
		kind ecosystem.CandidateFailureKind
		code string
	}{
		{"manager", ecosystem.CandidateFailureManager, "package_manager_failure"},
		{"non-json", ecosystem.CandidateFailureNonJSON, "package_output_non_json"},
		{"truncated", ecosystem.CandidateFailureTruncatedJSON, "package_output_truncated_json"},
		{"schema", ecosystem.CandidateFailureSchemaMismatch, "package_output_schema_mismatch"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"packageManager":"pnpm@10.14.0"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			workspace := config.Workspace{
				Name: "pnpm-output", Path: root, Stack: config.StackNode,
				PackageManager: "pnpm", Platform: "linux/amd64",
			}
			runners := scanStageRunners{
				vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
					return nil, nil, nil, "trivy", false, nil
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
					return nil, false, nil
				},
				packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
					return nil, "pnpm", false, &ecosystem.CandidateError{
						Kind: testCase.kind, Manager: "pnpm", ExitCode: 2,
					}
				},
			}
			result := scanOneTargetWith(
				context.Background(), config.Config{},
				scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace},
				scanOptions{only: "packages"}, config.LocalPackagePolicy{},
				updatesnapshot.PolicyIdentity{}, 0, runners,
			)
			if result.Status != "failed" || result.Error == nil || result.Error.Code != testCase.code ||
				result.PackageUpdates == nil || result.PackageUpdates.Reason != testCase.code {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestRuntimeConstraintFailuresAreTypedPartialCapabilities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, constraint, wantCode string
	}{
		{"invalid", ">=twenty", ecosystem.RuntimeConstraintInvalid},
		{"unsupported syntax", ">=20 || >=24", ecosystem.RuntimeConstraintUnsupportedSyntax},
		{"no compatible runtime", "25.0.0", ecosystem.RuntimeConstraintNoCompatible},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if err := os.WriteFile(
				filepath.Join(root, "package.json"),
				[]byte(fmt.Sprintf(`{"engines":{"node":%q}}`, testCase.constraint)),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(root, "package-lock.json"),
				[]byte(`{"lockfileVersion":3}`),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			workspace := config.Workspace{
				Name: "runtime-constraint", Path: root, Stack: config.StackNode,
				PackageManager: "npm", Platform: "linux/amd64",
			}
			runners := scanStageRunners{
				vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
					return nil, nil, nil, "trivy", false, nil
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
					return nil, false, nil
				},
				packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
					t.Fatal("package scanner ran after runtime constraint resolution failed")
					return nil, "", false, nil
				},
				prepareToolchain: func(_ context.Context, cfg config.Config, workspace config.Workspace) (toolchain.Prepared, error) {
					selection, err := toolchain.Select(workspace, cfg)
					return toolchain.Prepared{Selection: selection}, err
				},
			}
			result := scanOneTargetWith(
				context.Background(), config.Config{},
				scanTarget{workspace: &workspace, name: workspace.Name, path: root, origin: updatesnapshot.OriginWorkspace},
				scanOptions{only: "packages"}, config.LocalPackagePolicy{},
				updatesnapshot.PolicyIdentity{}, 0, runners,
			)
			if result.Status != "partial" || result.Error == nil ||
				result.Error.Code != testCase.wantCode ||
				!strings.Contains(result.Error.Hint, "override") {
				t.Fatalf("scan result = %#v", result)
			}
			if result.PackageUpdates == nil ||
				result.PackageUpdates.Status != "unavailable" ||
				result.PackageUpdates.Reason != testCase.wantCode {
				t.Fatalf("package update capability = %#v", result.PackageUpdates)
			}
		})
	}
}

func TestScanJSONEnvelopeRepresentsCleanFindingsReadyScanOnlyPartialAndFailed(t *testing.T) {
	results := []scanResult{
		{Project: "clean", Status: "clean", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{}},
		{Project: "findings", Status: "findings", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{"CVE-1"}, Tools: []scanToolResult{}, Warnings: []string{}},
		{Project: "docs", Status: config.VerificationScanOnly, Candidates: []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Target: "2.0.0"}}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{}},
		{Project: "ready", Status: "ready", SnapshotID: "snapshot", Candidates: []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Target: "2.0.0"}}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{}},
		{Project: "partial", Status: "partial", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{"CVE-2"}, Tools: []scanToolResult{}, Warnings: []string{}, Error: &jsonCommandError{Code: "package_scan_failed", Message: "package scan failed", Stage: "candidate"}},
		{Project: "failed", Status: "failed", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{}, Error: &jsonCommandError{Code: "scan_failed", Message: "failed"}},
	}
	summary := summarizeScan(results)
	data, err := json.Marshal(jsonCommandEnvelope{Format: 1, Command: "scan", Results: results, Summary: summary, Warnings: []string{}, Errors: []jsonCommandError{}})
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if summary.Clean != 1 || summary.Findings != 1 || summary.ScanOnly != 1 || summary.Ready != 1 || summary.Partial != 1 || summary.Failed != 1 || summary.Vulnerabilities != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	// A "clean" result must never coexist with vulnerabilities or candidates.
	for _, result := range results {
		if result.Status == "clean" && (len(result.Vulnerabilities) > 0 || len(result.Candidates) > 0) {
			t.Fatalf("project %q is clean but has findings", result.Project)
		}
	}
	// Partial results have a stable exit code distinct from a total failure.
	if resultErr := scanResultError(summary, "vulnerabilities", false); resultErr == nil {
		t.Fatal("expected a failure exit code when a partial result is present")
	} else {
		var coded commandError
		if !errors.As(resultErr, &coded) || coded.code != exitPartial {
			t.Fatalf("error = %#v, want exit %d", resultErr, exitPartial)
		}
	}
}

func TestHumanScanOutputUsesCompactTableAndOptionalDetails(t *testing.T) {
	previousExecutable := executableName
	executableName = "vuelta"
	t.Cleanup(func() { executableName = previousExecutable })

	result := scanResult{
		Project: "api", Directory: "/tmp/project", Status: "ready", SnapshotID: "snapshot-id",
		Timeout: "4m0s",
		Candidates: []updatesnapshot.Candidate{{
			Kind: "npm", Name: "lodash", Current: "4.17.20", Target: "4.17.23", ReleaseAgeVerified: true,
		}},
		Vulnerabilities: []string{"CVE-2024-1"},
		VulnerabilityFindings: []vulnscan.Finding{
			{ID: "CVE-2024-1", Package: "lodash", Severity: "HIGH"},
		},
		Stages: []scanStageResult{
			{Name: stageCandidate, Status: string(stageSucceeded)},
			{Name: stageVulnerability, Status: string(stageNotRequested)},
		},
		InputCategories: []string{"package-lock", "package-manifest"},
		Warnings:        []string{"built a local scanner image"},
	}

	stdout, stderr := captureScanOutput(t, func() {
		writeHumanScanResults([]scanResult{result}, "/tmp/config.yaml", false, nil)
	})
	for _, wanted := range []string{
		"Scan: api", "Project timeout: 4m0s", "Packages:", "MANAGER", "PACKAGE", "CURRENT", "LATEST", "STATUS",
		"npm", "lodash", "4.17.20", "4.17.23", "available",
		"Result: 1 package update available; 1 vulnerability found.",
		"Vulnerabilities:", "CVE", "SEVERITY", "CVE-2024-1", "HIGH",
		"Next: vuelta update local --directory /tmp/project --config /tmp/config.yaml",
	} {
		if !strings.Contains(stdout, wanted) {
			t.Fatalf("compact output %q does not contain %q", stdout, wanted)
		}
	}
	for _, hidden := range []string{"Details:", "stage ", "inputs:", "built a local scanner image"} {
		if strings.Contains(stdout, hidden) || strings.Contains(stderr, hidden) {
			t.Fatalf("compact output exposed %q: stdout=%q stderr=%q", hidden, stdout, stderr)
		}
	}

	stdout, stderr = captureScanOutput(t, func() {
		writeHumanScanResults([]scanResult{result}, "/tmp/config.yaml", true, nil)
	})
	for _, wanted := range []string{"Details:", "stage candidate:", "inputs:"} {
		if !strings.Contains(stdout, wanted) {
			t.Fatalf("verbose stdout %q does not contain %q", stdout, wanted)
		}
	}
	if !strings.Contains(stderr, "Warnings:") || !strings.Contains(stderr, "Warning: built a local scanner image") {
		t.Fatalf("verbose stderr = %q", stderr)
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

func TestHumanScanOutputExplainsRequirementsReadOnly(t *testing.T) {
	result := scanResult{
		Directory: "/tmp/project", Status: config.VerificationScanOnly,
		Candidates: []updatesnapshot.Candidate{{Kind: "requirements", Name: "flask", Current: "0.5", Target: "3.1.3"}},
		Stages:     []scanStageResult{{Name: stageCandidate, Status: string(stageSucceeded)}},
		PackageUpdates: &packageUpdateAvailability{
			Status: config.VerificationScanOnly, Reason: "manifest_has_no_safe_mutation_contract",
		},
	}
	stdout, _ := captureScanOutput(t, func() {
		writeHumanScanResults([]scanResult{result}, "/tmp/config.yaml", false, nil)
	})
	for _, wanted := range []string{
		"requirements", "flask", "0.5", "3.1.3", "read-only",
		"Result: 1 package update found (read-only).",
		"Note: requirements.txt is read-only; automatic updates are unavailable.",
	} {
		if !strings.Contains(stdout, wanted) {
			t.Fatalf("read-only output %q does not contain %q", stdout, wanted)
		}
	}
}

func TestProjectScanReportIsBoundedEscapedAndNamesSnapshotAuthority(t *testing.T) {
	created := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	expires := created.Add(time.Hour)
	result := scanResult{
		Project: "api<script>", Directory: "/projects/api", Status: "ready",
		Timeout:    "4m0s",
		SnapshotID: "abcdefghijklmnopqrstuv", SnapshotCreated: &created, SnapshotExpires: &expires,
		Candidates: []updatesnapshot.Candidate{{
			Kind: "npm", Name: "bad|name", Current: "1.0.0", Target: "2.0.0", ReleaseAgeVerified: true,
		}},
		Vulnerabilities: []string{"[link](https://example.invalid) <script>"},
		Warnings:        []string{"warning\nwith newline", "https://user:password@example.invalid/private"},
	}
	data, err := buildProjectScanReport(result, scanOptions{directory: "/projects/api"}, created)
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	if !strings.Contains(report, "Project timeout: `4m0s`") {
		t.Fatalf("report does not record the effective project timeout: %s", report)
	}
	for _, wanted := range []string{
		"Status: **ready**", "bad\\|name", "&lt;script&gt;", "abcdefghijklmnopqrstuv",
		"vuelta update local --directory /projects/api", "authority is the selected JSON snapshot",
	} {
		if !strings.Contains(report, wanted) {
			t.Fatalf("report lacks %q:\n%s", wanted, report)
		}
	}
	if strings.Contains(report, "<script>") || strings.Contains(report, "\nwith newline") || strings.Contains(report, "user:password") {
		t.Fatalf("report contains unescaped external Markdown/HTML:\n%s", report)
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

func TestFinalizeCleanOrFindingsPromotesOnlyDefaultClean(t *testing.T) {
	clean := finalizeCleanOrFindings(scanResult{Status: "clean"})
	if clean.Status != "clean" {
		t.Fatalf("status = %q, want clean", clean.Status)
	}
	findings := finalizeCleanOrFindings(scanResult{Status: "clean", Vulnerabilities: []string{"CVE-1"}})
	if findings.Status != "findings" {
		t.Fatalf("status = %q, want findings", findings.Status)
	}
	findingsFromCandidates := finalizeCleanOrFindings(scanResult{Status: "clean", Candidates: []updatesnapshot.Candidate{{Name: "example"}}})
	if findingsFromCandidates.Status != "findings" {
		t.Fatalf("status = %q, want findings", findingsFromCandidates.Status)
	}
	scanOnly := finalizeCleanOrFindings(scanResult{Status: config.VerificationScanOnly, Vulnerabilities: []string{"CVE-1"}})
	if scanOnly.Status != config.VerificationScanOnly {
		t.Fatalf("status = %q, want unchanged scan-only status", scanOnly.Status)
	}
}

func TestFailedScanResultPreservesEarlierSucceededStageAsPartial(t *testing.T) {
	result := scanResult{Status: "clean", Vulnerabilities: []string{}, Candidates: []updatesnapshot.Candidate{}, Stages: []scanStageResult{}}
	result = addStage(result, stagePreflight, stageSucceeded, "")
	result = addStage(result, stageVulnerability, stageSucceeded, "")
	result.Vulnerabilities = []string{"CVE-1", "CVE-2"}

	failed := failedScanResult(result, stageCandidate, "package_scan_failed", errors.New("package scan failed"), "hint")
	if failed.Status != "partial" {
		t.Fatalf("status = %q, want partial", failed.Status)
	}
	if len(failed.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities were lost: %#v", failed.Vulnerabilities)
	}
	if failed.Error == nil || failed.Error.Stage != stageCandidate {
		t.Fatalf("error stage = %#v, want %q", failed.Error, stageCandidate)
	}
}

func TestFailedScanResultWithNoPriorDataStageIsFullyFailed(t *testing.T) {
	result := scanResult{Status: "clean", Vulnerabilities: []string{}, Candidates: []updatesnapshot.Candidate{}, Stages: []scanStageResult{}}
	result = addStage(result, stagePreflight, stageSucceeded, "")

	failed := failedScanResult(result, stageVulnerability, "vulnerability_scan_failed", errors.New("scanner unavailable"), "hint")
	if failed.Status != "failed" {
		t.Fatalf("status = %q, want failed", failed.Status)
	}
}

func TestFailedScanResultSurfacesSafeCategoryExitCodeAndBoundedDetailForDockerFailures(t *testing.T) {
	executor := dockerexec.New(dockerexec.Options{
		Resolver: func(string) (string, error) {
			path := filepath.Join(t.TempDir(), "docker")
			script := "#!/bin/sh\nif [ \"$3\" = version ]; then echo '{\"server_version\":\"28.3.2\",\"api_version\":\"1.49\",\"os\":\"linux\",\"architecture\":\"arm64\"}'; exit 0; fi\nif [ \"$3\" = info ]; then echo '{\"id\":\"daemon-approved\",\"security_options\":[\"name=seccomp,profile=builtin\"]}'; exit 0; fi\necho 'permission denied: token=supersecret' 1>&2\nexit 5\n"
			if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			return path, nil
		},
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
		Endpoint: dockerexec.Endpoint{SocketPath: "/approved/docker.sock", Expected: dockerexec.DaemonIdentity{
			ID: "daemon-approved", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
			MinimumAPIVersion: "1.44", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
		}},
		EndpointValidator: func(dockerexec.Endpoint) (string, error) { return "/approved/docker.sock", nil },
	})
	_, runErr := executor.Run(context.Background(), dockerexec.Request{
		Args:   []string{"run"},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	wrapped := fmt.Errorf("docker run trivy: %w", runErr)

	result := scanResult{Status: "clean", Vulnerabilities: []string{}, Candidates: []updatesnapshot.Candidate{}, Stages: []scanStageResult{}}
	failed := failedScanResult(result, stageVulnerability, "vulnerability_scan_failed", wrapped, "hint")
	if failed.Error.Category != "permission" {
		t.Fatalf("category = %q, want permission", failed.Error.Category)
	}
	if failed.Error.ExitCode == nil || *failed.Error.ExitCode != 5 {
		t.Fatalf("exit code = %v, want 5", failed.Error.ExitCode)
	}
	if strings.Contains(failed.Error.StderrTail, "supersecret") {
		t.Fatalf("stderr tail leaked secret: %q", failed.Error.StderrTail)
	}
	if strings.Contains(failed.Error.Message, "supersecret") {
		t.Fatalf("message leaked secret: %q", failed.Error.Message)
	}
	if len(failed.Warnings) != 1 || !strings.Contains(failed.Warnings[0], "category=permission") || strings.Contains(failed.Warnings[0], "supersecret") {
		t.Fatalf("warning is not actionable and redacted: %#v", failed.Warnings)
	}
}

func TestProjectConfigIsIgnoredUnlessExplicitlyAllowed(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".npmrc"), []byte("registry=https://example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := config.Workspace{Path: directory, Stack: config.StackNode, PackageManager: "npm"}
	contract, err := scaninput.PackageContract(workspace, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range contract.Files {
		if file.Path == ".npmrc" {
			t.Fatal("project config entered the default scan contract")
		}
	}
	contract, err = scaninput.PackageContract(workspace, true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range contract.Files {
		found = found || file.Path == ".npmrc"
	}
	if !found {
		t.Fatal("explicitly allowed project config is missing from scan contract")
	}
}

func TestScanPolicyCannotHideProjectConfigOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("allowed_packages:\n  - example\nallow_project_config: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadScanPolicy(path)
	if err == nil || !strings.Contains(err.Error(), "pass --allow-project-config explicitly") {
		t.Fatalf("policy error = %v", err)
	}
}

func TestLoadScanPolicyRecordsCanonicalPathAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("allowed_packages:\n  - example\nmin_release_age_days: 14\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, identity, err := loadScanPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.MinReleaseAgeDays != 14 || !filepath.IsAbs(identity.Path) || identity.Hash == "" || identity.Hash == updatesnapshot.PolicyNone {
		t.Fatalf("policy = %#v, identity = %#v", policy, identity)
	}
}

func writeScanVerifyCompose(t *testing.T, root, digest string) string {
	t.Helper()
	path := filepath.Join(root, "compose.verify.yml")
	content := fmt.Sprintf(`services:
  verify:
    image: node:24-bookworm-slim@%s
    platform: linux/arm64
    user: "1000:1000"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    cpus: "1"
    mem_limit: 1g
    pids_limit: 256
    networks: [verification]
    command: ["npm", "run", "build"]
networks:
  verification:
    internal: true
`, digest)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckVerificationImageMatchingDigestHasNoWarning(t *testing.T) {
	root := t.TempDir()
	digest := "sha256:" + strings.Repeat("1", 64)
	writeScanVerifyCompose(t, root, digest)
	calls := 0
	warning := checkVerificationImage(context.Background(), root, "refresh command", func(_ context.Context, ref, platform string) (string, error) {
		calls++
		if ref != "node:24-bookworm-slim" {
			t.Fatalf("reference = %q", ref)
		}
		if platform != "linux/arm64" {
			t.Fatalf("platform = %q", platform)
		}
		return digest, nil
	})
	if warning != nil || calls != 1 {
		t.Fatalf("warning = %#v, resolver calls = %d", warning, calls)
	}
}

func TestCheckVerificationImageDriftIsStructuredVisibleAndReadOnly(t *testing.T) {
	root := t.TempDir()
	pinned := "sha256:" + strings.Repeat("1", 64)
	current := "sha256:" + strings.Repeat("2", 64)
	path := writeScanVerifyCompose(t, root, pinned)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	command := "vuelta project verify init --directory " + root + " --refresh-image"
	warning := checkVerificationImage(context.Background(), root, command, func(context.Context, string, string) (string, error) {
		return current, nil
	})
	if warning == nil || warning.Code != "verification_base_image_stale" || warning.RefreshCommand != command {
		t.Fatalf("warning = %#v", warning)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("staleness check modified compose.verify.yml")
	}
	result := scanResult{
		Directory: root, Status: "clean", Timeout: time.Minute.String(),
		Warnings: []string{warning.Message}, VerificationImage: warning,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"verification_image_warning", "verification_base_image_stale", "refresh_command", warning.Message} {
		if !strings.Contains(string(encoded), wanted) {
			t.Fatalf("JSON result is missing %q: %s", wanted, encoded)
		}
	}
	_, stderr := captureScanOutput(t, func() {
		writeHumanScanResults([]scanResult{result}, "", false, nil)
	})
	if strings.Count(stderr, warning.Message) != 1 {
		t.Fatalf("text warning count = %d, stderr = %q", strings.Count(stderr, warning.Message), stderr)
	}
}

func TestCheckVerificationImageUnavailableRegistryAndMissingFileAreQuiet(t *testing.T) {
	root := t.TempDir()
	called := false
	if warning := checkVerificationImage(context.Background(), root, "refresh", func(context.Context, string, string) (string, error) {
		called = true
		return "", errors.New("registry unavailable")
	}); warning != nil || called {
		t.Fatalf("missing profile warning = %#v, resolver called = %v", warning, called)
	}
	writeScanVerifyCompose(t, root, "sha256:"+strings.Repeat("1", 64))
	if warning := checkVerificationImage(context.Background(), root, "refresh", func(context.Context, string, string) (string, error) {
		return "", errors.New("registry unavailable")
	}); warning != nil {
		t.Fatalf("registry failure warning = %#v", warning)
	}
}
