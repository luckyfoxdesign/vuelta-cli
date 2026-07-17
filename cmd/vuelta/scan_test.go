package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/localexec"
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

func TestParseScanOptionsOnlyModesAndExecution(t *testing.T) {
	for _, test := range []struct {
		args      []string
		only      string
		execution string
		wantErr   bool
	}{
		{args: []string{"--only", "vulnerabilities"}, only: "vulnerabilities", execution: "container"},
		{args: []string{"--only", "packages", "--execution", "local"}, only: "packages", execution: "local"},
		{args: []string{"--only", "other"}, wantErr: true},
		{args: []string{"--execution", "automatic"}, wantErr: true},
	} {
		options, _, err := parseScanOptions(test.args)
		if (err != nil) != test.wantErr {
			t.Fatalf("parse %v error = %v, wantErr %t", test.args, err, test.wantErr)
		}
		if !test.wantErr && (options.only != test.only || options.execution != test.execution) {
			t.Fatalf("parse %v = %#v", test.args, options)
		}
	}
}

func TestValidateScanExecutionAllowsLocalOnlyForAdhoc(t *testing.T) {
	local := scanOptions{execution: "local"}
	if err := validateScanExecution([]scanTarget{{origin: updatesnapshot.OriginAdhoc}}, local); err != nil {
		t.Fatalf("adhoc local execution: %v", err)
	}
	if err := validateScanExecution([]scanTarget{{origin: updatesnapshot.OriginWorkspace, name: "api"}}, local); err == nil || !strings.Contains(err.Error(), "container-only") {
		t.Fatalf("workspace local error = %v", err)
	}
}

func TestLocalScannerUsesCanonicalBinaryAndPrivateEnvironment(t *testing.T) {
	t.Setenv("PATH", "/hostile/bin")
	t.Setenv("HTTPS_PROXY", "http://hostile.invalid")
	t.Setenv("TRIVY_CONFIG", "/hostile/trivy.yaml")
	t.Setenv("GITHUB_TOKEN", "must-not-leak")
	project := t.TempDir()
	toolRoot := t.TempDir()
	target := filepath.Join(toolRoot, "trusted-trivy")
	if err := os.WriteFile(target, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(toolRoot, "trivy")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Fatal(err)
	}
	wantBinary, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	var privateRoot string
	command := localScannerCommandWith(
		func(name string) (string, error) {
			if name != "trivy" {
				t.Fatalf("resolver name = %q", name)
			}
			return link, nil
		},
		func(_ context.Context, binary, dir string, args, env []string, stdoutBytes, stderrBytes int) (localexec.Result, error) {
			if binary != wantBinary || !filepath.IsAbs(binary) || dir != project {
				t.Fatalf("runner binary=%q dir=%q", binary, dir)
			}
			if len(args) == 0 || args[len(args)-1] != project {
				t.Fatalf("scanner args = %q", args)
			}
			if stdoutBytes != localScannerStdoutMaxBytes || stderrBytes != localScannerStderrTailMaxBytes {
				t.Fatalf("scanner caps = %d/%d", stdoutBytes, stderrBytes)
			}
			values := make(map[string]string, len(env))
			for _, item := range env {
				name, value, ok := strings.Cut(item, "=")
				if !ok {
					t.Fatalf("invalid environment entry %q", item)
				}
				values[name] = value
			}
			for _, forbidden := range []string{"HTTPS_PROXY", "TRIVY_CONFIG", "GITHUB_TOKEN"} {
				if _, ok := values[forbidden]; ok {
					t.Fatalf("hostile variable %s was inherited", forbidden)
				}
			}
			if values["PATH"] == "/hostile/bin" {
				t.Fatal("caller PATH was inherited")
			}
			privateRoot = filepath.Dir(values["HOME"])
			for _, path := range []string{privateRoot, values["HOME"], values["XDG_CACHE_HOME"], values["XDG_CONFIG_HOME"], values["TMPDIR"]} {
				info, statErr := os.Stat(path)
				if statErr != nil || info.Mode().Perm() != 0o700 {
					t.Fatalf("private path %q info=%v error=%v", path, info, statErr)
				}
			}
			return localexec.Result{Output: []byte("{}")}, nil
		},
	)
	output, err := command(context.Background(), project, "trivy", "fs", "/project")
	if err != nil || string(output) != "{}" {
		t.Fatalf("scanner output=%q error=%v", output, err)
	}
	if _, err := os.Stat(privateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private invocation root still exists: %v", err)
	}
}

func TestPreflightRejectsWritableLocalScanner(t *testing.T) {
	project := t.TempDir()
	binary := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(binary, []byte("test executable"), 0o722); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binary, 0o722); err != nil {
		t.Fatal(err)
	}
	err := preflightScanEnvironmentWith(
		config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy"}},
		[]scanTarget{{path: project, origin: updatesnapshot.OriginAdhoc}},
		scanOptions{execution: "local", only: "vulnerabilities"},
		func(string) (string, error) { return binary, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("preflight error = %v", err)
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

func TestScanJSONEnvelopeRepresentsCleanReadyAndPartialFailure(t *testing.T) {
	results := []scanResult{
		{Project: "clean", Status: "clean", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{"CVE-1"}, Tools: []scanToolResult{}, Warnings: []string{}},
		{Project: "docs", Status: config.VerificationScanOnly, Candidates: []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Target: "2.0.0"}}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{}},
		{Project: "ready", Status: "ready", SnapshotID: "snapshot", Candidates: []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Target: "2.0.0"}}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{}},
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
	if summary.Clean != 1 || summary.ScanOnly != 1 || summary.Ready != 1 || summary.Failed != 1 || summary.Vulnerabilities != 1 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestEnsureProjectConfigRequiresExplicitOptIn(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".npmrc"), []byte("registry=https://example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureProjectConfigAllowed(directory, "npm", false); err == nil || !strings.Contains(err.Error(), "--allow-project-config") {
		t.Fatalf("error = %v", err)
	}
	if err := ensureProjectConfigAllowed(directory, "npm", true); err != nil {
		t.Fatalf("explicit opt-in: %v", err)
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
