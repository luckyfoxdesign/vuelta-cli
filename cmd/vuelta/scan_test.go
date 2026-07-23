package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

func TestResolveScanTargetsUsesContainingRegisteredProject(t *testing.T) {
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
	targets, err := resolveScanTargets(cfg, scanOptions{}, func() (string, error) { return working, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].name != "api" || targets[0].path != nested || targets[0].origin != updatesnapshot.OriginWorkspace {
		t.Fatalf("targets = %#v", targets)
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

func TestEffectiveMinReleaseAge(t *testing.T) {
	for _, test := range []struct {
		value      string
		configured int
		policy     int
		want       time.Duration
	}{
		{configured: 7, policy: 14, want: 14 * 24 * time.Hour},
		{value: "0", configured: 7, policy: 14, want: 0},
		{value: "12h", configured: 7, policy: 14, want: 12 * time.Hour},
		{value: "7d", want: 7 * 24 * time.Hour},
	} {
		got, err := effectiveMinReleaseAge(test.value, test.configured, test.policy)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("effective age for %q = %s, want %s", test.value, got, test.want)
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
				vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
					return nil, "trivy", false, nil
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) { return nil, false, nil },
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

func TestScanExitPriorityPrefersFailedResultOverFindings(t *testing.T) {
	err := scanResultError(scanSummary{Failed: 1, Vulnerabilities: 3}, "vulnerabilities")
	var coded commandError
	if !errors.As(err, &coded) || coded.code != exitFailure {
		t.Fatalf("error = %#v, want exit %d", err, exitFailure)
	}
	err = scanResultError(scanSummary{Vulnerabilities: 3}, "vulnerabilities")
	if !errors.As(err, &coded) || coded.code != exitFindings {
		t.Fatalf("error = %#v, want exit %d", err, exitFindings)
	}
}

func TestScanExitCodeDistinguishesMixedResultsFromTotalFailure(t *testing.T) {
	var coded commandError
	if err := scanResultError(scanSummary{Failed: 1, Succeeded: 1}, ""); !errors.As(err, &coded) || coded.code != exitPartial {
		t.Fatalf("mixed result error = %#v, want exit %d", err, exitPartial)
	}
	if err := scanResultError(scanSummary{Partial: 1}, ""); !errors.As(err, &coded) || coded.code != exitPartial {
		t.Fatalf("partial result error = %#v, want exit %d", err, exitPartial)
	}
	if err := scanResultError(scanSummary{Failed: 2}, ""); !errors.As(err, &coded) || coded.code != exitFailure {
		t.Fatalf("total failure error = %#v, want exit %d", err, exitFailure)
	}
	if err := scanResultError(scanSummary{Succeeded: 2}, ""); err != nil {
		t.Fatalf("clean scan error = %v", err)
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
				vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
					if test.dependencySource == "github-dependabot" {
						return nil, "trivy-images", false, nil
					}
					return []string{"CVE-1"}, "trivy", true, test.vulnerabilityErr
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) {
					if test.dependencySource != "github-dependabot" {
						return nil, false, nil
					}
					return []string{"GHSA-1"}, true, test.alertErr
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

func TestStandaloneRequirementsVulnerabilityOnlyRunsScanner(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := scanTarget{path: root, origin: updatesnapshot.OriginAdhoc}
	vulnerabilityCalled := false
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			vulnerabilityCalled = true
			return []string{"CVE-2026-0001"}, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) { return nil, false, nil },
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
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			return []string{"CVE-2026-0001"}, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) { return nil, false, nil },
		packages: func(_ context.Context, _ config.Config, _ scanTarget, options scanOptions, _ config.LocalPackagePolicy, _ time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			if options.packageDiagnostics != nil {
				*options.packageDiagnostics = append(*options.packageDiagnostics, updater.ScanDiagnostic{File: "requirements.txt", Line: 2, Code: "exact_pin_required", Message: "expected one exact pin"})
			}
			return []updatesnapshot.Candidate{{Kind: "requirements", Name: "flask", Current: "0.5", Target: "3.1.2"}}, "requirements", false, nil
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
	if !containsSubstring(result.Warnings, "no update snapshot") {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if !containsSubstring(result.Warnings, "release age could not be verified") {
		t.Fatalf("release-age warnings = %#v", result.Warnings)
	}
	if err := scanResultError(summarizeScan([]scanResult{result}), ""); err != nil {
		t.Fatalf("scan-only findings returned failure exit: %v", err)
	}
}

func TestStandaloneRequirementsPackagesOnlyIsScanOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			t.Fatal("vulnerability scanner was called for --only packages")
			return nil, "", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) {
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
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			called = true
			return nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) { return nil, false, nil },
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
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			return nil, "trivy-images", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) {
			alertsCalled = true
			return []string{"GHSA-1"}, true, nil
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
}

func TestFailedWorkspaceDoesNotStopSupportedWorkspace(t *testing.T) {
	root := t.TempDir()
	workspace := config.Workspace{Name: "supported", Path: root, Stack: config.StackNode, PackageManager: "npm"}
	runners := scanStageRunners{
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			return nil, "trivy", true, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) { return nil, false, nil },
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
	if err := scanResultError(summary, ""); !errors.As(err, &coded) || coded.code != exitPartial {
		t.Fatalf("mixed workspace exit = %#v, want %d", err, exitPartial)
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
		vulnerabilities: func(context.Context, config.Config, scanTarget) ([]string, string, bool, error) {
			return nil, "trivy", false, nil
		},
		alerts: func(context.Context, config.Config, scanTarget) ([]string, bool, error) { return nil, false, nil },
		packages: func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
			return nil, "npm", true, nil
		},
		prepareToolchain: func(_ context.Context, _ config.Config, workspace config.Workspace) (toolchain.Prepared, error) {
			if workspace.Name == "broken" {
				return toolchain.Prepared{}, errors.New("embedded scanner build failed")
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
	if broken.Status != "partial" || broken.Error == nil || broken.Error.Code != "toolchain_incompatible" || !strings.Contains(broken.Error.Hint, "override") {
		t.Fatalf("broken result = %#v", broken)
	}
	if supported.Status != "clean" || hasFailedStage(supported, stageCandidate) {
		t.Fatalf("supported result = %#v", supported)
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
	if resultErr := scanResultError(summary, "vulnerabilities"); resultErr == nil {
		t.Fatal("expected a failure exit code when a partial result is present")
	} else {
		var coded commandError
		if !errors.As(resultErr, &coded) || coded.code != exitPartial {
			t.Fatalf("error = %#v, want exit %d", resultErr, exitPartial)
		}
	}
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
