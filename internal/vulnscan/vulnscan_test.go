package vulnscan

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
)

func trivyJSON(updated string) string {
	return `{"Metadata":{"DBUpdatedAt":"` + updated + `"},"Results":[{"Target":"poetry.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"example","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"HIGH"}]}]}`
}

func trivyImageJSON(updated, repoDigest string) string {
	return `{"Metadata":{"DBUpdatedAt":"` + updated + `","RepoDigests":["` + repoDigest + `"]},"Results":[]}`
}

func adhocNPMWorkspace(t *testing.T) (string, config.Workspace) {
	t.Helper()
	root := t.TempDir()
	for name, contents := range map[string]string{
		"package.json": `{}`, "package-lock.json": `{"lockfileVersion":3}`, "unrelated-source.js": "sentinel",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm"}
}

func TestScanParsesFreshStructuredTrivyResultWithoutIgnoreFlags(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	var args []string
	scanner := NewAdhocScanner(func(_ context.Context, dir string, _ string, got ...string) ([]byte, error) {
		if _, err := os.Stat(filepath.Join(dir, "unrelated-source.js")); !os.IsNotExist(err) {
			t.Fatalf("unrelated source is visible to scanner: %v", err)
		}
		args = got
		return []byte(trivyJSON(now.Add(-time.Hour).Format(time.RFC3339))), nil
	})
	scanner.Now = func() time.Time { return now }
	root, workspace := adhocNPMWorkspace(t)
	report, err := scanner.Scan(context.Background(), root, workspace, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("Scan() = %+v, %v", report, err)
	}
	if strings.Contains(strings.Join(args, " "), "ignore") {
		t.Fatalf("scanner must not hide findings through command flags: %v", args)
	}
	if !contains(args, "--include-dev-deps") {
		t.Fatalf("scanner must include development dependencies: %v", args)
	}
}

func TestManifestOnlyNPMDependencyScanArchivesOnlyPackageJSON(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"demo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unrelated-source.js"), []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := NewAdhocScanner(func(_ context.Context, dir, _ string, _ ...string) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil || string(data) != `{"name":"demo"}` {
			t.Fatalf("package.json = %q, %v", data, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "package-lock.json")); !os.IsNotExist(err) {
			t.Fatalf("package-lock.json entered manifest-only archive: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "unrelated-source.js")); !os.IsNotExist(err) {
			t.Fatalf("unrelated source entered manifest-only archive: %v", err)
		}
		return []byte(`{"Metadata":{"DBUpdatedAt":"` + now.Add(-time.Hour).Format(time.RFC3339) + `"},"Results":[]}`), nil
	})
	scanner.Now = func() time.Time { return now }
	report, err := scanner.Scan(context.Background(), root, config.Workspace{
		Path: root, Stack: config.StackNode, PackageManager: "npm",
	}, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "trivy", DatabaseMaxAgeHours: 24,
	}})
	if err != nil || len(report.Findings) != 0 {
		t.Fatalf("Scan() = %#v, %v", report, err)
	}
}

func TestStandaloneRequirementsReachesSelectedDependencyScanner(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, source, output string
		wantArg              string
	}{
		{
			name: "trivy", source: "trivy", wantArg: "fs",
			output: trivyJSON(now.Add(-time.Hour).Format(time.RFC3339)),
		},
		{
			name: "osv", source: "osv-scanner", wantArg: "--lockfile",
			output: `{"database_updated_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","results":[{"source":{"path":"requirements.txt"},"packages":[{"package":{"name":"flask"},"groups":[{"ids":["CVE-2026-0002"],"packages":[{"version":"0.5"}]}]}]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("flask==0.5\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "unrelated.py"), []byte("sentinel\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			called := false
			scanner := NewAdhocScanner(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
				called = true
				if name != test.source || !contains(args, test.wantArg) {
					t.Fatalf("scanner command = %s %v", name, args)
				}
				if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err != nil || string(data) != "flask==0.5\n" {
					t.Fatalf("requirements input = %q, %v", data, err)
				}
				if _, err := os.Stat(filepath.Join(dir, "unrelated.py")); !os.IsNotExist(err) {
					t.Fatalf("unrelated input entered scanner context: %v", err)
				}
				return []byte(test.output), nil
			})
			scanner.Now = func() time.Time { return now }
			report, err := scanner.Scan(context.Background(), root, config.Workspace{
				Path: root, Stack: config.StackPython,
			}, config.Config{VulnScan: config.VulnScanConfig{
				DependencySource: test.source, DatabaseMaxAgeHours: 24,
			}})
			if err != nil || !called || len(report.Findings) != 1 {
				t.Fatalf("Scan() = %+v, %v; called=%t", report, err, called)
			}
		})
	}
}

func TestScanRejectsStaleDatabase(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	scanner := NewAdhocScanner(func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
		return []byte(trivyJSON(now.Add(-25 * time.Hour).Format(time.RFC3339))), nil
	})
	scanner.Now = func() time.Time { return now }
	root, workspace := adhocNPMWorkspace(t)
	_, err := scanner.Scan(context.Background(), root, workspace, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
	if err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("expected stale database error, got %v", err)
	}
}

func TestScanAcceptsTrivyResultWithoutDatabaseTimestampFromFreshTmpfs(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	scanner := NewAdhocScanner(func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"Results":[]}`), nil
	})
	scanner.Now = func() time.Time { return now }
	root, workspace := adhocNPMWorkspace(t)
	report, err := scanner.Scan(context.Background(), root, workspace, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
	if err != nil || len(report.Findings) != 0 {
		t.Fatalf("Scan() = %+v, %v", report, err)
	}
}

func TestScanImagesUsesOSPackagesOnlyWithoutDependencyScan(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	digest := "registry.example/service@sha256:" + strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM "+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	scanner := NewAdhocScanner(func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args)
		return []byte(trivyJSON(now.Format(time.RFC3339))), nil
	})
	scanner.Now = func() time.Time { return now }
	report, err := scanner.ScanImages(context.Background(), root, config.Workspace{
		Path: root, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}},
	}, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "github-dependabot", DatabaseMaxAgeHours: 24,
		ImageScan: config.ImageScanConfig{Enabled: true, Tool: "trivy", Image: "scanner@sha256:" + strings.Repeat("b", 64)},
	}})
	if err != nil || len(report.Findings) != 1 || len(commands) != 1 {
		t.Fatalf("ScanImages() = %+v, %v; commands=%v", report, err, commands)
	}
	if !contains(commands[0], "--pkg-types") || !contains(commands[0], "os") {
		t.Fatalf("image scan must restrict packages to OS packages: %v", commands[0])
	}
	if contains(commands[0], "fs") || contains(commands[0], "--include-dev-deps") {
		t.Fatalf("image scan must not run a dependency filesystem scan: %v", commands[0])
	}
}

func TestScanReportsDependencyToolProgress(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	var progress []struct {
		detail      string
		done, total int
	}
	scanner := NewAdhocScanner(
		func(context.Context, string, string, ...string) ([]byte, error) {
			return []byte(trivyJSON(now.Format(time.RFC3339))), nil
		},
		WithDependencyProgress(func(detail string, done, total int) {
			progress = append(progress, struct {
				detail      string
				done, total int
			}{detail: detail, done: done, total: total})
		}),
	)
	scanner.Now = func() time.Time { return now }
	root, workspace := adhocNPMWorkspace(t)
	if _, err := scanner.Scan(context.Background(), root, workspace, config.Config{
		VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24},
	}); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		detail      string
		done, total int
	}{{detail: "trivy fs", done: 1, total: 1}}
	if !reflect.DeepEqual(progress, want) {
		t.Fatalf("progress = %#v, want %#v", progress, want)
	}
}

func TestScanImagesReportsIntentPlatformProgressInCommandOrder(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM alpine:3.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var commands int
	var progress []struct {
		detail      string
		done, total int
	}
	scanner := NewAdhocScanner(
		func(context.Context, string, string, ...string) ([]byte, error) {
			commands++
			return []byte(trivyImageJSON(now.Format(time.RFC3339), "example@sha256:"+strings.Repeat("a", 64))), nil
		},
		WithImageProgress(func(detail string, done, total int) {
			progress = append(progress, struct {
				detail      string
				done, total int
			}{detail: detail, done: done, total: total})
		}),
	)
	scanner.Now = func() time.Time { return now }
	_, err := scanner.ScanImages(context.Background(), root, config.Workspace{
		Path: root,
		DockerImages: &config.DockerImagesSpec{
			Files:         []string{"Dockerfile"},
			RuntimeImages: []string{"registry.example/app:latest"},
			Platforms:     []string{"linux/amd64", "linux/arm64"},
		},
	}, config.Config{VulnScan: config.VulnScanConfig{
		DatabaseMaxAgeHours: 24,
		ImageScan: config.ImageScanConfig{
			Enabled: true, Tool: "trivy", Image: "scanner@sha256:" + strings.Repeat("b", 64),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		detail      string
		done, total int
	}{
		{detail: "Preparing scan input"},
		{detail: "alpine:3.20 (linux/amd64)", done: 1, total: 4},
		{detail: "alpine:3.20 (linux/arm64)", done: 2, total: 4},
		{detail: "registry.example/app:latest (linux/amd64)", done: 3, total: 4},
		{detail: "registry.example/app:latest (linux/arm64)", done: 4, total: 4},
	}
	if commands != 4 || !reflect.DeepEqual(progress, want) {
		t.Fatalf("commands = %d, progress = %#v, want %#v", commands, progress, want)
	}
}

func TestScanImagesResolvesBareTagAsBaseImageProxyAndRecordsDigest(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM node:20-alpine\nRUN apk add curl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "node@sha256:" + strings.Repeat("b", 64)
	scanner := NewAdhocScanner(func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
		if !contains(args, "node:20-alpine") {
			t.Fatalf("expected trivy to be invoked with the bare tag, got %v", args)
		}
		return []byte(trivyImageJSON(now.Format(time.RFC3339), digest)), nil
	})
	scanner.Now = func() time.Time { return now }
	report, err := scanner.ScanImages(context.Background(), root, config.Workspace{
		Path: root, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}},
	}, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "github-dependabot", DatabaseMaxAgeHours: 24,
		ImageScan: config.ImageScanConfig{Enabled: true, Tool: "trivy", Image: "scanner@sha256:" + strings.Repeat("c", 64)},
	}})
	if err != nil {
		t.Fatalf("ScanImages() error = %v", err)
	}
	if len(report.ImageResolutions) != 1 {
		t.Fatalf("resolutions = %#v", report.ImageResolutions)
	}
	resolution := report.ImageResolutions[0]
	if resolution.Reference != "node:20-alpine" || resolution.ResolvedDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("resolution = %#v", resolution)
	}
	if resolution.Tier != TierBaseImageTag {
		t.Fatalf("tier = %d, want TierBaseImageTag", resolution.Tier)
	}
	if !resolution.OSPackagesInstalled {
		t.Fatal("Dockerfile installs OS packages; the honesty downgrade flag must be set")
	}
	if resolution.Dockerfile != "Dockerfile" {
		t.Fatalf("dockerfile = %q", resolution.Dockerfile)
	}
	if !resolution.ResolvedAt.Equal(now) {
		t.Fatalf("resolvedAt = %v, want %v", resolution.ResolvedAt, now)
	}
}

func TestScanImagesUnresolvableTagIsStructuredSkipNotHardFailure(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM privateregistry.internal/base:unreachable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, errors.New("dial tcp: lookup privateregistry.internal: no such host")
	})
	scanner.Now = func() time.Time { return now }
	report, err := scanner.ScanImages(context.Background(), root, config.Workspace{
		Path: root, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}},
	}, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "github-dependabot", DatabaseMaxAgeHours: 24,
		ImageScan: config.ImageScanConfig{Enabled: true, Tool: "trivy", Image: "scanner@sha256:" + strings.Repeat("c", 64)},
	}})
	if err != nil {
		t.Fatalf("an unresolvable tag must be a structured skip, not a hard scan failure: %v", err)
	}
	if len(report.ImageSkips) != 1 || report.ImageSkips[0].Reference != "privateregistry.internal/base:unreachable" {
		t.Fatalf("skips = %#v", report.ImageSkips)
	}
	if report.ImageSkips[0].Reason == "" {
		t.Fatal("skip must carry a visible reason, never a bare warning string")
	}
}

func TestScanImagesNoImageReferenceIsStructuredSkip(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stepCalls int
	scanner := NewAdhocScanner(
		func(context.Context, string, string, ...string) ([]byte, error) {
			t.Fatal("trivy must not be invoked when nothing is resolvable")
			return nil, nil
		},
		WithImageProgress(func(_ string, done, _ int) {
			if done > 0 {
				stepCalls++
			}
		}),
	)
	report, err := scanner.ScanImages(context.Background(), root, config.Workspace{
		Path: root, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}},
	}, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "github-dependabot", DatabaseMaxAgeHours: 24,
		ImageScan: config.ImageScanConfig{Enabled: true, Tool: "trivy", Image: "scanner@sha256:" + strings.Repeat("c", 64)},
	}})
	if err != nil {
		t.Fatalf("FROM scratch must be a structured skip, not a hard failure: %v", err)
	}
	if len(report.ImageSkips) != 1 {
		t.Fatalf("skips = %#v", report.ImageSkips)
	}
	if stepCalls != 0 {
		t.Fatalf("image step callback called %d times without image intents", stepCalls)
	}
}

func TestScanImagesExplicitDigestFailureRemainsHardFailure(t *testing.T) {
	root := t.TempDir()
	digest := "registry.example/service@sha256:" + strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM "+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, errors.New("registry unavailable")
	})
	_, err := scanner.ScanImages(context.Background(), root, config.Workspace{
		Path: root, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}},
	}, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "github-dependabot", DatabaseMaxAgeHours: 24,
		ImageScan: config.ImageScanConfig{Enabled: true, Tool: "trivy", Image: "scanner@sha256:" + strings.Repeat("c", 64)},
	}})
	if err == nil {
		t.Fatal("a digest-pinned (tier 1) scan failure must remain a hard failure, unchanged from prior behavior")
	}
}

func TestDockerCommandRejectsUnpinnedImageBeforeStartingDocker(t *testing.T) {
	_, err := dockerCommand(context.Background(), scaninput.Bundle{}, "aquasec/trivy:latest", config.EgressConfig{}, "trivy", "fs", "/project")
	if err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("expected unpinned image rejection, got %v", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
