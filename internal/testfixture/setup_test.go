package testfixture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
)

func fixturesRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "fixtures", "projects")
}

func TestSetupProjectCreatesIndependentGitRepositories(t *testing.T) {
	for _, name := range []string{"py-poetry-ok", "py-poetry-real-ok", "py-uv-ok", "py-pip-tools-ok", "py-requirements-only-cve", "node-pnpm-ok", "node-npm-ok", "node-bun-ok", "docker-app-ok", "py-poetry-failtest", "node-pnpm-cve", "docker-app-cve", "malicious-postinstall", "escape-symlink"} {
		t.Run(name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), name)
			if err := SetupProject(context.Background(), fixturesRoot(t), name, destination); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("git", "status", "--porcelain")
			cmd.Dir = destination
			out, err := cmd.Output()
			if err != nil || strings.TrimSpace(string(out)) != "" {
				t.Fatalf("fixture repository is not clean: %q, %v", out, err)
			}
			if _, err := os.Stat(filepath.Join(destination, ".git")); err != nil {
				t.Fatalf("fixture git metadata: %v", err)
			}
		})
	}
}

func TestGitHubAlertsHandlerPaginatesWithoutRetainingToken(t *testing.T) {
	server := httptest.NewTLSServer(GitHubAlertsHandler{RequireToken: true, Token: "fixture-token"})
	defer server.Close()
	t.Setenv("VUELTA_GITHUB_TOKEN", "fixture-token")
	client := githubalerts.Client{Transport: server.Client().Transport, RemoteURL: func(context.Context, string, string) (string, error) {
		return "git@github.com:acme/widget.git", nil
	}}
	findings, err := client.Scan(context.Background(), config.Workspace{Path: t.TempDir(), Remote: "origin"}, config.GithubAdvisoriesConfig{APIURL: server.URL, TokenEnv: "VUELTA_GITHUB_TOKEN"})
	if err != nil || len(findings) != 2 {
		t.Fatalf("Scan() = %+v, %v", findings, err)
	}
}

func TestRegistryCapturesDigestBeforeMutableTagChanges(t *testing.T) {
	oldDigest := "sha256:" + strings.Repeat("a", 64)
	newDigest := "sha256:" + strings.Repeat("b", 64)
	registry := NewRegistry(map[string]string{"registry.fixture/app:1": oldDigest})
	captured, err := registry.Resolve(context.Background(), "registry.fixture/app:1")
	if err != nil {
		t.Fatal(err)
	}
	registry.SetTag("registry.fixture/app:1", newDigest)
	if captured != oldDigest {
		t.Fatalf("captured digest = %q, want immutable %q", captured, oldDigest)
	}
	if current, err := registry.Resolve(context.Background(), "registry.fixture/app:1"); err != nil || current != newDigest {
		t.Fatalf("current digest = %q, %v", current, err)
	}
	var _ updater.DigestResolver = registry.Resolve
}

func TestGitHubHandlerIsReadOnly(t *testing.T) {
	server := httptest.NewServer(GitHubAlertsHandler{})
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/repos/acme/widget/dependabot/alerts", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
	}
}
