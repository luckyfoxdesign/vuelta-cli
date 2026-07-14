package vulnscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func trivyJSON(updated string) string {
	return `{"Metadata":{"DBUpdatedAt":"` + updated + `"},"Results":[{"Target":"poetry.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"example","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"HIGH"}]}]}`
}

func TestScanParsesFreshStructuredTrivyResultWithoutIgnoreFlags(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	var args []string
	scanner := Scanner{
		Now: func() time.Time { return now },
		Command: func(_ context.Context, _ string, _ string, got ...string) ([]byte, error) {
			args = got
			return []byte(trivyJSON(now.Add(-time.Hour).Format(time.RFC3339))), nil
		},
	}
	root := t.TempDir()
	report, err := scanner.Scan(context.Background(), root, config.Workspace{Path: root}, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
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
	scanner := Scanner{
		Now: func() time.Time { return now },
		Command: func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
			return []byte(trivyJSON(now.Add(-25 * time.Hour).Format(time.RFC3339))), nil
		},
	}
	root := t.TempDir()
	_, err := scanner.Scan(context.Background(), root, config.Workspace{Path: root}, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
	if err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("expected stale database error, got %v", err)
	}
}

func TestScanAcceptsTrivyResultWithoutDatabaseTimestampFromFreshTmpfs(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	scanner := Scanner{
		Now: func() time.Time { return now },
		Command: func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
			return []byte(`{"Results":[]}`), nil
		},
	}
	report, err := scanner.Scan(context.Background(), t.TempDir(), config.Workspace{}, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
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
	scanner := Scanner{
		Now: func() time.Time { return now },
		Command: func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
			commands = append(commands, args)
			return []byte(trivyJSON(now.Format(time.RFC3339))), nil
		},
	}
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

func TestDockerRunArgsUseReadOnlyHardenedScannerContainer(t *testing.T) {
	got := dockerRunArgs(
		"aquasec/trivy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"/sandbox/project",
		"vuelta-update-egress",
		"http://vuelta-egress-proxy:3128",
		"trivy",
		[]string{"fs", "--format", "json", "/project"},
	)
	for _, want := range []string{
		"--user", "65532:65532",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "1",
		"--memory", "2g",
		"--pids-limit", "256",
		"--network", "vuelta-update-egress",
		"HTTP_PROXY=http://vuelta-egress-proxy:3128",
		"TRIVY_CACHE_DIR=/tmp/trivy",
		"TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db",
		"/tmp:rw,noexec,nosuid,size=2g",
		"type=bind,src=/sandbox/project,dst=/project,readonly",
		"aquasec/trivy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if !contains(got, want) {
			t.Fatalf("docker args missing %q: %q", want, got)
		}
	}
	if contains(got, "/var/run/docker.sock") || contains(got, "host") {
		t.Fatalf("docker args must not expose a Docker socket or host namespace: %q", got)
	}
}

func TestDockerCommandRejectsUnpinnedImageBeforeStartingDocker(t *testing.T) {
	_, err := dockerCommand(context.Background(), t.TempDir(), "aquasec/trivy:latest", config.EgressConfig{}, "trivy", "fs", "/project")
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
