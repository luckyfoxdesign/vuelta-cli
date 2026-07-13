package vulnscan

import (
	"context"
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
	report, err := scanner.Scan(context.Background(), root, config.Workspace{Path: root}, config.VulnScanConfig{Enabled: true, Tool: "trivy", DatabaseMaxAgeHours: 24})
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("Scan() = %+v, %v", report, err)
	}
	if strings.Contains(strings.Join(args, " "), "ignore") {
		t.Fatalf("scanner must not hide findings through command flags: %v", args)
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
	_, err := scanner.Scan(context.Background(), root, config.Workspace{Path: root}, config.VulnScanConfig{Enabled: true, Tool: "trivy", DatabaseMaxAgeHours: 24})
	if err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("expected stale database error, got %v", err)
	}
}
