package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestDefaultSecurityGateRunsOnlySelectedLocalDependencySource(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	localCalls := 0
	githubCalls := 0
	scanner := vulnscan.NewAdhocScanner(func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
		localCalls++
		return []byte(`{"Metadata":{"DBUpdatedAt":"` + now.Format(time.RFC3339) + `"},"Results":[{"Target":"package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"example","InstalledVersion":"1.0.0","Severity":"HIGH"}]}]}`), nil
	})
	scanner.Now = func() time.Time { return now }
	gate := DefaultSecurityGate{
		Scanner: scanner,
		GitHub: githubalerts.Client{RemoteURL: func(context.Context, string, string) (string, error) {
			githubCalls++
			return "", errors.New("GitHub must not run for a local source")
		}},
	}
	cfg := config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24}}
	root := t.TempDir()
	for name := range map[string]bool{"package.json": true, "package-lock.json": true} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ws := config.Workspace{Path: root, Remote: "origin", Stack: config.StackNode, PackageManager: "npm"}
	baseline, err := gate.Baseline(context.Background(), ws, cfg)
	if err != nil || len(baseline.details) != 1 || localCalls != 1 || githubCalls != 0 {
		t.Fatalf("Baseline() = %+v, %v; local=%d github=%d", baseline, err, localCalls, githubCalls)
	}
	post, err := gate.PostCheck(context.Background(), ws.Path, ws, cfg, baseline)
	if err != nil || len(post.details) != 1 || localCalls != 2 || githubCalls != 0 {
		t.Fatalf("PostCheck() = %+v, %v; local=%d github=%d", post, err, localCalls, githubCalls)
	}
}

func TestDefaultSecurityGateRunsDependabotWithoutLocalDependencyScan(t *testing.T) {
	githubCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/dependabot/alerts" {
			http.NotFound(w, r)
			return
		}
		githubCalls++
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	localCalls := 0
	gate := DefaultSecurityGate{
		Scanner: vulnscan.Scanner{Command: func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
			localCalls++
			return nil, errors.New("local scanner must not run for Dependabot")
		}},
		GitHub: githubalerts.Client{
			Transport: server.Client().Transport,
			RemoteURL: func(context.Context, string, string) (string, error) { return "git@github.com:acme/widget.git", nil },
		},
	}
	cfg := config.Config{
		VulnScan:         config.VulnScanConfig{DependencySource: "github-dependabot", FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24},
		GithubAdvisories: config.GithubAdvisoriesConfig{APIURL: server.URL},
	}
	report, err := gate.Baseline(context.Background(), config.Workspace{Path: t.TempDir(), Remote: "origin"}, cfg)
	if err != nil || !report.Ran || localCalls != 0 || githubCalls != 1 {
		t.Fatalf("Baseline() = %+v, %v; local=%d github=%d", report, err, localCalls, githubCalls)
	}
}

func TestDefaultSecurityGateFailsClosedForSelectedDependabot(t *testing.T) {
	gate := DefaultSecurityGate{GitHub: githubalerts.Client{RemoteURL: func(context.Context, string, string) (string, error) {
		return "", errors.New("API unavailable")
	}}}
	cfg := config.Config{VulnScan: config.VulnScanConfig{DependencySource: "github-dependabot", FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24}}
	_, err := gate.Baseline(context.Background(), config.Workspace{Path: t.TempDir(), Remote: "origin"}, cfg)
	if err == nil || !strings.Contains(err.Error(), "required GitHub Dependabot") {
		t.Fatalf("expected selected Dependabot failure to block, got %v", err)
	}
}
