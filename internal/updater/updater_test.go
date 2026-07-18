package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeRunWritingLock(lockFile, newContent string, callCount *int) DockerRunner {
	return func(_ context.Context, _ string, _ []string, workDir string) (string, error) {
		*callCount++
		return "", os.WriteFile(filepath.Join(workDir, lockFile), []byte(newContent), 0o644)
	}
}

func TestPoetryUpdaterDetectsChange(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poetry.lock", "old\n")
	var calls int
	u := PoetryUpdater{Image: "python@sha256:x", Run: fakeRunWritingLock("poetry.lock", "new\n", &calls)}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if calls != 1 {
		t.Fatalf("expected exactly one docker invocation, got %d", calls)
	}
}

func TestPoetryUpdaterNoChange(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poetry.lock", "same\n")
	var calls int
	u := PoetryUpdater{Image: "python@sha256:x", Run: fakeRunWritingLock("poetry.lock", "same\n", &calls)}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false")
	}
}

func TestPoetryUpdaterPropagatesTimeout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poetry.lock", "old\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	u := PoetryUpdater{
		Image: "python@sha256:x",
		Run: func(ctx context.Context, _ string, _ []string, _ string) (string, error) {
			return "", ctx.Err()
		},
	}

	_, err := u.Update(ctx, dir)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
}

func TestRunDockerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := RunDocker(ctx, "example.invalid/image", nil, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestResolveDigestViaManifestHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ResolveDigestViaManifest(ctx, "example.invalid/image:latest")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestNPMUpdaterUsesPinnedNCUVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", "old\n")
	var capturedArgs [][]string
	run := func(_ context.Context, _ string, args []string, workDir string) (string, error) {
		capturedArgs = append(capturedArgs, append([]string(nil), args...))
		if len(capturedArgs) == 2 {
			return "", os.WriteFile(filepath.Join(workDir, "package-lock.json"), []byte("new\n"), 0o644)
		}
		return "", nil
	}
	u := NPMUpdater{Image: "node@sha256:x", NCUVersion: "17.1.16", Run: run}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	want := [][]string{
		{"npx", "npm-check-updates@17.1.16", "-u"},
		{"npm", "install"},
	}
	if !reflect.DeepEqual(capturedArgs, want) {
		t.Fatalf("unexpected npm argv: got %#v, want %#v", capturedArgs, want)
	}
}

func TestNPMUpdaterRejectsInvalidNCUVersionBeforeRunning(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", "old\n")
	calls := 0
	u := NPMUpdater{
		Image:      "node@sha256:x",
		NCUVersion: "17.1.16; touch /tmp/pwned",
		Run: func(context.Context, string, []string, string) (string, error) {
			calls++
			return "", nil
		},
	}

	_, err := u.Update(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "exact semantic version") {
		t.Fatalf("expected invalid version error, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("runner was called %d times for an invalid version", calls)
	}
}

func TestBunUpdaterUsesSeparateArgv(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bun.lock", "old\n")
	var capturedArgs [][]string
	u := BunUpdater{
		Image:      "bun@sha256:x",
		NCUVersion: "17.1.16",
		Run: func(_ context.Context, _ string, args []string, workDir string) (string, error) {
			capturedArgs = append(capturedArgs, append([]string(nil), args...))
			if len(capturedArgs) == 2 {
				return "", os.WriteFile(filepath.Join(workDir, "bun.lock"), []byte("new\n"), 0o644)
			}
			return "", nil
		},
	}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	want := [][]string{
		{"bunx", "npm-check-updates@17.1.16", "-u"},
		{"bun", "install"},
	}
	if !reflect.DeepEqual(capturedArgs, want) {
		t.Fatalf("unexpected bun argv: got %#v, want %#v", capturedArgs, want)
	}
}

func TestRunDockerFailsClosedWithoutEgressPolicy(t *testing.T) {
	_, err := RunDocker(context.Background(), "node@sha256:x", []string{"npm", "install"}, t.TempDir())
	if !errors.Is(err, ErrEgressPolicyUnavailable) {
		t.Fatalf("expected ErrEgressPolicyUnavailable, got %v", err)
	}
}

func TestDockerRunArgsIncludeSecurityBaseline(t *testing.T) {
	got := dockerRunArgs("node@sha256:x", []string{"npm", "install"}, "/sandbox/project", "vuelta-update-egress", "http://vuelta-egress-proxy:3128")
	for _, want := range []string{
		"--user", "65532:65532",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "1",
		"--memory", "1g",
		"--pids-limit", "256",
		"--network", "vuelta-update-egress",
		"HTTP_PROXY=http://vuelta-egress-proxy:3128",
		"HTTPS_PROXY=http://vuelta-egress-proxy:3128",
		"--env", "HOME=/tmp",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	} {
		if !slicesContain(got, want) {
			t.Fatalf("docker args missing %q: %q", want, got)
		}
	}
	if slicesContain(got, "/var/run/docker.sock") || slicesContain(got, "host") {
		t.Fatalf("docker args must not expose a Docker socket or host namespace: %q", got)
	}
}

func TestDockerRunArgsIncludeProfilePlatform(t *testing.T) {
	got := dockerRunArgsForProfile("node@sha256:x", []string{"npm", "install"}, "/sandbox/project", "vuelta-update-egress", "http://vuelta-egress-proxy:3128", "10001:10001", "linux/arm64")
	if !slicesContain(got, "--platform") || !slicesContain(got, "linux/arm64") {
		t.Fatalf("docker args missing profile platform: %q", got)
	}
}

func TestParsePackageCandidates(t *testing.T) {
	candidates, err := parsePackageCandidates("npm", []byte(`{"left-pad":"1.3.0","@scope/pkg":"2.0.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].Target == "" || candidates[1].Name == "" {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestPackageScannerReceivesOnlyMinimalBundle(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{}`)
	writeFile(t, root, "package-lock.json", `{}`)
	writeFile(t, root, "unrelated-source.js", "sentinel")
	contract, err := scaninput.PackageContract(config.Workspace{Stack: config.StackNode, PackageManager: "npm"}, false)
	if err != nil {
		t.Fatal(err)
	}
	scanner := packageScanner{
		Kind: "npm", Image: "node@sha256:" + strings.Repeat("a", 64), Contract: contract,
		Run: func(_ context.Context, _ string, _ []string, bundle scaninput.Bundle) (string, error) {
			if _, ok := bundle.Content("package.json"); !ok {
				t.Fatal("package manifest missing from minimal bundle")
			}
			if _, ok := bundle.Content("package-lock.json"); !ok {
				t.Fatal("package lock missing from minimal bundle")
			}
			if _, ok := bundle.Content("unrelated-source.js"); ok {
				t.Fatal("unrelated source visible to package scanner")
			}
			return `{"example":"2.0.0"}`, nil
		},
	}
	candidates, err := scanner.Scan(context.Background(), root)
	if err != nil || len(candidates) != 1 || candidates[0].Name != "example" {
		t.Fatalf("Scan() = %#v, %v", candidates, err)
	}
}

type fakeExitCode int

func (e fakeExitCode) Error() string { return "command failed" }
func (e fakeExitCode) ExitCode() int { return int(e) }

func TestPNPMScannerAcceptsExitOneOnlyAfterStrictJSONParsing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{}`)
	writeFile(t, root, "pnpm-lock.yaml", `lockfileVersion: '9.0'`)
	contract, err := scaninput.PackageContract(config.Workspace{Stack: config.StackNode, PackageManager: "pnpm"}, false)
	if err != nil {
		t.Fatal(err)
	}
	scanner := packageScanner{
		Kind: "pnpm", Image: "node@sha256:" + strings.Repeat("a", 64), Contract: contract,
		Run: func(context.Context, string, []string, scaninput.Bundle) (string, error) {
			return `{"lodash":{"latest":"4.18.1","wanted":"4.17.20","dependencyType":"dependencies"}}`, fakeExitCode(1)
		},
	}
	candidates, err := scanner.Scan(context.Background(), root)
	if err != nil || len(candidates) != 1 || candidates[0].Name != "lodash" || candidates[0].Target != "4.18.1" {
		t.Fatalf("Scan() = %#v, %v", candidates, err)
	}
	scanner.Run = func(context.Context, string, []string, scaninput.Bundle) (string, error) {
		return `not-json`, fakeExitCode(1)
	}
	if _, err := scanner.Scan(context.Background(), root); err == nil || !strings.Contains(err.Error(), "parse pnpm") {
		t.Fatalf("malformed exit-one output error = %v", err)
	}
}

func TestProfileScannerUsesInstalledNCUAndExactProfileImage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"engines":{"node":"24.x"},"packageManager":"npm@11.4.2"}`)
	writeFile(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	image := "registry.example/vuelta/node24-npm@sha256:" + strings.Repeat("a", 64)
	profile := config.ToolchainProfile{
		Version: config.ToolchainProfileVersion, ID: "node24-npm", Stack: config.StackNode, PackageManager: "npm",
		Runtime: "24", PackageManagerVersion: "11.4.2", Scanner: "ncu", ScannerVersion: "18.1.1",
		Image: image, Platform: "linux/amd64", User: "10001:10001", LockFormats: []string{"npm-v3"},
		Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: true, ReleaseAge: true},
	}
	ws := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64", ToolchainProfile: profile.ID}
	cfg := config.Config{Update: config.UpdateConfig{MinReleaseAgeDays: 7, ToolchainProfiles: []config.ToolchainProfile{profile}}}
	resolved, err := ResolveCandidateScannerWithOptions(ws, cfg, CandidateScannerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	combined, ok := resolved.(combinedScanner)
	if !ok || len(combined) != 1 {
		t.Fatalf("scanner = %T %#v", resolved, resolved)
	}
	packageScan, ok := combined[0].(packageScanner)
	if !ok || packageScan.Image != image || !reflect.DeepEqual(packageScan.Args, []string{"ncu", "--jsonUpgraded", "--removeRange", "--cooldown", "168"}) {
		t.Fatalf("profile scanner = %#v", combined[0])
	}
	if args, err := plannedArgs("npm", updatesnapshot.Candidate{Kind: "npm", Name: "example", Target: "2.0.0"}, cfg, &profile, false); err != nil || !reflect.DeepEqual(args, []string{"ncu", "--filter", "example", "--cooldown", "168", "-u"}) {
		t.Fatalf("plannedArgs() = %#v, %v", args, err)
	}
}

func TestPlannedNPMUpdateAppliesOnlyReviewedTargetAndKeepsDependenciesForVerification(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"example":"^1.0.0"}}`)
	writeFile(t, root, "package-lock.json", `{"lockfileVersion":3,"version":"before"}`)
	candidate := updatesnapshot.Candidate{Kind: "npm", Name: "example", Target: "2.0.0"}
	calls := 0
	u := PlannedUpdater{
		Candidates: []updatesnapshot.Candidate{candidate},
		Workspace:  config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm"},
		Config: config.Config{Update: config.UpdateConfig{
			MinReleaseAgeDays: 7,
			Images:            map[string]string{"node": "node@sha256:x"},
			Tools:             map[string]string{"npm_check_updates": "22.2.9"},
		}},
		Validate: func(context.Context) error { return nil },
		Recheck:  staticCandidateScanner{candidates: []updatesnapshot.Candidate{candidate}},
		Run: func(_ context.Context, _ string, args []string, workDir string) (string, error) {
			calls++
			switch calls {
			case 1:
				want := []string{"npx", "npm-check-updates@22.2.9", "--filter", "example", "--cooldown", "168", "-u"}
				if !reflect.DeepEqual(args, want) {
					t.Fatalf("ncu argv = %#v, want %#v", args, want)
				}
				return "", os.WriteFile(filepath.Join(workDir, "package.json"), []byte(`{"dependencies":{"example":"^2.0.0"}}`), 0o644)
			case 2:
				want := []string{"npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"}
				if !reflect.DeepEqual(args, want) {
					t.Fatalf("npm argv = %#v, want %#v", args, want)
				}
				if err := os.Mkdir(filepath.Join(workDir, "node_modules"), 0o755); err != nil {
					return "", err
				}
				return "", os.WriteFile(filepath.Join(workDir, "package-lock.json"), []byte(`{"lockfileVersion":3,"version":"after"}`), 0o644)
			default:
				t.Fatalf("unexpected updater call %d", calls)
				return "", nil
			}
		},
	}
	changed, err := u.Update(context.Background(), root)
	if err != nil || !changed || calls != 2 {
		t.Fatalf("Update() = %t, %v; calls=%d", changed, err, calls)
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Fatalf("verification dependencies were not retained in sandbox: %v", err)
	}
}

func TestProfilePipToolsScannerUsesProjectPinMetadataCommand(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pyproject.toml", "[project]\nrequires-python = \">=3.12,<3.13\"\n")
	writeFile(t, root, "requirements.in", "requests==2.31.0\n")
	writeFile(t, root, "requirements.txt", "requests==2.31.0\n")
	image := "registry.example/vuelta/python312-pip-tools@sha256:" + strings.Repeat("a", 64)
	profile := config.ToolchainProfile{
		Version: config.ToolchainProfileVersion, ID: "python312-pip-tools", Stack: config.StackPython, PackageManager: "pip-tools",
		Runtime: "3.12", PackageManagerVersion: "7.5.0", Scanner: "vuelta-pip-tools-scan", ScannerVersion: "1.0.0",
		Image: image, Platform: "linux/amd64", User: "10001:10001", LockFormats: []string{"requirements"},
		Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: true},
	}
	ws := config.Workspace{Path: root, Stack: config.StackPython, PackageManager: "pip-tools", Platform: "linux/amd64", ToolchainProfile: profile.ID}
	cfg := config.Config{Update: config.UpdateConfig{ToolchainProfiles: []config.ToolchainProfile{profile}}}
	resolved, err := ResolveCandidateScannerWithOptions(ws, cfg, CandidateScannerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	combined, ok := resolved.(combinedScanner)
	if !ok || len(combined) != 1 {
		t.Fatalf("scanner = %T %#v", resolved, resolved)
	}
	packageScan, ok := combined[0].(packageScanner)
	if !ok || packageScan.Image != image || !reflect.DeepEqual(packageScan.Args, []string{"vuelta-pip-tools-scan"}) {
		t.Fatalf("profile scanner = %#v", combined[0])
	}
}

func TestLegacyBunScannerFailsBeforeDockerResolution(t *testing.T) {
	ws := config.Workspace{Stack: config.StackNode, PackageManager: "bun"}
	_, err := ResolveCandidateScannerWithOptions(ws, config.Config{}, CandidateScannerOptions{})
	if err == nil || !strings.Contains(err.Error(), "mandatory egress proxy") {
		t.Fatalf("bun scanner error = %v", err)
	}
}

func TestPlannedPipToolsUpdateRewritesPinThenCompilesOnce(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.in", "requests[socks] == 2.31.0 # direct\n")
	writeFile(t, root, "requirements.txt", "requests==2.31.0\n")
	candidate := updatesnapshot.Candidate{Kind: "pip-tools", Name: "requests", Current: "2.31.0", Target: "2.32.4"}
	calls := 0
	u := PlannedUpdater{
		Candidates: []updatesnapshot.Candidate{candidate},
		Workspace:  config.Workspace{Path: root, Stack: config.StackPython, PackageManager: "pip-tools"},
		Config:     config.Config{Update: config.UpdateConfig{Images: map[string]string{"python-pip-tools": "python@sha256:x"}}},
		Validate:   func(context.Context) error { return nil },
		Recheck:    staticCandidateScanner{candidates: []updatesnapshot.Candidate{candidate}},
		Run: func(_ context.Context, _ string, args []string, workDir string) (string, error) {
			calls++
			if !reflect.DeepEqual(args, []string{"pip-compile", "requirements.in"}) {
				t.Fatalf("pip-tools argv = %#v", args)
			}
			manifest, err := os.ReadFile(filepath.Join(workDir, "requirements.in"))
			if err != nil {
				return "", err
			}
			if string(manifest) != "requests[socks] == 2.32.4 # direct\n" {
				t.Fatalf("rewritten requirements.in = %q", manifest)
			}
			return "", os.WriteFile(filepath.Join(workDir, "requirements.txt"), []byte("requests==2.32.4\n"), 0o644)
		},
	}
	changed, err := u.Update(context.Background(), root)
	if err != nil || !changed || calls != 1 {
		t.Fatalf("Update() = %t, %v; calls = %d", changed, err, calls)
	}
}

func TestRewritePipToolsPinRejectsUnpinnedInput(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.in", "requests>=2.31.0\n")
	err := rewritePipToolsPin(root, updatesnapshot.Candidate{Kind: "pip-tools", Name: "requests", Current: "2.31.0", Target: "2.32.4"})
	if err == nil || !strings.Contains(err.Error(), "exactly one direct exact pin") {
		t.Fatalf("rewrite error = %v", err)
	}
}

func TestPlannedUpdaterDoesNotWriteWhenSnapshotValidationFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", "unchanged\n")
	called := false
	u := PlannedUpdater{
		Candidates: []updatesnapshot.Candidate{{Kind: "npm", Name: "example", Target: "1.2.3"}},
		Validate:   func(context.Context) error { return errors.New("stale snapshot") },
		Recheck:    fakeCandidateScanner{called: &called},
	}
	if _, err := u.Update(context.Background(), dir); err == nil {
		t.Fatal("expected validation error")
	}
	if called {
		t.Fatal("candidate recheck must not run after failed validation")
	}
	data, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "unchanged\n" {
		t.Fatalf("project changed after failed validation: %q", data)
	}
}

type fakeCandidateScanner struct{ called *bool }

func (f fakeCandidateScanner) Scan(context.Context, string) ([]updatesnapshot.Candidate, error) {
	*f.called = true
	return nil, nil
}

type staticCandidateScanner struct{ candidates []updatesnapshot.Candidate }

func (s staticCandidateScanner) Scan(context.Context, string) ([]updatesnapshot.Candidate, error) {
	return append([]updatesnapshot.Candidate(nil), s.candidates...), nil
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestResolveMissingImageErrors(t *testing.T) {
	ws := config.Workspace{Stack: config.StackPython, PackageManager: "poetry"}
	cfg := config.Config{}
	if _, err := Resolve(ws, cfg); err == nil {
		t.Fatal("expected error for missing update.images[python-poetry]")
	}
}

func TestResolvePoetry(t *testing.T) {
	ws := config.Workspace{Stack: config.StackPython, PackageManager: "poetry"}
	cfg := config.Config{Update: config.UpdateConfig{Images: map[string]string{"python-poetry": "python@sha256:x"}}}
	u, err := Resolve(ws, cfg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := u.(PoetryUpdater); !ok {
		t.Fatalf("expected PoetryUpdater, got %T", u)
	}
}

func TestResolveDockerStackWithoutImagesIsNoop(t *testing.T) {
	ws := config.Workspace{Stack: config.StackDocker}
	cfg := config.Config{}
	u, err := Resolve(ws, cfg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := u.(NoopUpdater); !ok {
		t.Fatalf("expected NoopUpdater, got %T", u)
	}
}

func TestResolveComposesPackageManagerAndDockerImages(t *testing.T) {
	ws := config.Workspace{
		Stack:          config.StackPython,
		PackageManager: "poetry",
		DockerImages:   &config.DockerImagesSpec{Files: []string{"Dockerfile"}},
	}
	cfg := config.Config{Update: config.UpdateConfig{Images: map[string]string{"python-poetry": "python@sha256:x"}}}
	u, err := Resolve(ws, cfg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := u.(CompositeUpdater); !ok {
		t.Fatalf("expected CompositeUpdater, got %T", u)
	}
}

func TestCompositeUpdaterOrAggregatesChanged(t *testing.T) {
	c := CompositeUpdater{
		fakeUpdater{changed: false},
		fakeUpdater{changed: true},
	}
	changed, err := c.Update(context.Background(), "/tmp")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when any sub-updater changed")
	}
}

type fakeUpdater struct{ changed bool }

func (f fakeUpdater) Update(context.Context, string) (bool, error) { return f.changed, nil }

func TestDockerImageUpdaterBumpsFromDigest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.12-slim@sha256:"+strings.Repeat("a", 64)+"\nRUN echo hi\n")

	resolver := func(_ context.Context, ref string) (string, error) {
		if ref != "python:3.12-slim" {
			t.Fatalf("unexpected ref passed to resolver: %q", ref)
		}
		return "sha256:" + strings.Repeat("b", 64), nil
	}
	u := DockerImageUpdater{Files: []string{"Dockerfile"}, Resolve: resolver}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if !strings.Contains(string(data), "FROM python:3.12-slim@sha256:"+strings.Repeat("b", 64)) {
		t.Fatalf("expected digest to be bumped, got: %s", data)
	}
}

func TestDockerImageUpdaterNoOpWhenDigestUnchanged(t *testing.T) {
	dir := t.TempDir()
	digest := "sha256:" + strings.Repeat("a", 64)
	writeFile(t, dir, "Dockerfile", "FROM python:3.12-slim@"+digest+"\n")

	resolver := func(_ context.Context, ref string) (string, error) { return digest, nil }
	u := DockerImageUpdater{Files: []string{"Dockerfile"}, Resolve: resolver}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false when the resolved digest matches the pinned one")
	}
}

func TestDockerImageUpdaterHandlesComposeImageLine(t *testing.T) {
	dir := t.TempDir()
	digest := strings.Repeat("c", 64)
	writeFile(t, dir, "compose.production.yml", "services:\n  web:\n    image: node:22@sha256:"+strings.Repeat("a", 64)+"\n")

	resolver := func(_ context.Context, ref string) (string, error) {
		if ref != "node:22" {
			t.Fatalf("unexpected ref: %q", ref)
		}
		return "sha256:" + digest, nil
	}
	u := DockerImageUpdater{Files: []string{"compose.production.yml"}, Resolve: resolver}

	changed, err := u.Update(context.Background(), dir)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "compose.production.yml"))
	if !strings.Contains(string(data), "image: node:22@sha256:"+digest) {
		t.Fatalf("expected image digest to be bumped, got: %s", data)
	}
}

func TestParseManifestDigestSingle(t *testing.T) {
	data := []byte(`{"Descriptor":{"digest":"sha256:` + strings.Repeat("d", 64) + `"}}`)
	digest, err := parseManifestDigest(data)
	if err != nil {
		t.Fatalf("parseManifestDigest: %v", err)
	}
	if digest != "sha256:"+strings.Repeat("d", 64) {
		t.Fatalf("unexpected digest: %q", digest)
	}
}

func TestParseManifestDigestList(t *testing.T) {
	data := []byte(`[{"Descriptor":{"digest":"sha256:` + strings.Repeat("e", 64) + `"}}]`)
	digest, err := parseManifestDigest(data)
	if err != nil {
		t.Fatalf("parseManifestDigest: %v", err)
	}
	if digest != "sha256:"+strings.Repeat("e", 64) {
		t.Fatalf("unexpected digest: %q", digest)
	}
}
