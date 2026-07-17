package vulnscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

func trivyJSON(updated string) string {
	return `{"Metadata":{"DBUpdatedAt":"` + updated + `"},"Results":[{"Target":"poetry.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"example","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"HIGH"}]}]}`
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
