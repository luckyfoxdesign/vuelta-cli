// Package githubalerts is a read-only client for GitHub Dependabot and
// Security Advisories APIs.
package githubalerts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

// Doer is the small HTTP boundary used by Client.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client makes read-only GitHub Dependabot and Global Security Advisories
// calls. Tokens are read only from TokenEnv and are never included in errors,
// scanner containers, or command-line arguments.
type Client struct {
	HTTPClient Doer
	RemoteURL  func(ctx context.Context, repoPath, remote string) (string, error)
}

func (c Client) httpClient() Doer {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c Client) remoteURL(ctx context.Context, repoPath, remote string) (string, error) {
	if c.RemoteURL != nil {
		return c.RemoteURL(ctx, repoPath, remote)
	}
	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", remote)
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("get remote URL for %q: %w", remote, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Scan returns open Dependabot alerts for a GitHub remote, enriched with
// Global Security Advisory data where available. A non-GitHub remote is not
// an error. For a required GitHub remote, every API/auth/rate-limit failure is
// returned so the caller can fail closed.
func (c Client) Scan(ctx context.Context, ws config.Workspace, cfg config.GithubAdvisoriesConfig) ([]vulnscan.Finding, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	remote, err := c.remoteURL(ctx, ws.Path, ws.Remote)
	if err != nil {
		return nil, c.requiredError(cfg, false, err)
	}
	owner, repo, githubRemote := githubRepository(remote)
	if !githubRemote {
		return nil, nil
	}
	alerts, err := c.dependabotAlerts(ctx, cfg, owner, repo)
	if err != nil {
		return nil, c.requiredError(cfg, true, err)
	}
	findings := make([]vulnscan.Finding, 0, len(alerts))
	for _, alert := range alerts {
		advisory, err := c.advisory(ctx, cfg, alert.Advisory.GHSAID)
		if err != nil {
			return nil, c.requiredError(cfg, true, err)
		}
		id := firstNonEmpty(advisory.GHSAID, alert.Advisory.GHSAID, alert.Advisory.CVEID)
		if id == "" || alert.Dependency.Package.Name == "" || alert.Dependency.ManifestPath == "" {
			return nil, c.requiredError(cfg, true, fmt.Errorf("dependabot alert %d has incomplete advisory or dependency data", alert.Number))
		}
		findings = append(findings, vulnscan.Finding{
			ID:               id,
			Package:          alert.Dependency.Package.Name,
			InstalledVersion: alert.Dependency.Scope,
			FixedVersion:     advisory.FirstPatchedVersion.Identifier,
			Severity:         strings.ToUpper(firstNonEmpty(advisory.Severity, alert.Advisory.Severity)),
			Target:           alert.Dependency.ManifestPath,
			Source:           "github-dependabot",
		})
	}
	return findings, nil
}

func (c Client) requiredError(cfg config.GithubAdvisoriesConfig, githubRemote bool, err error) error {
	if githubRemote && cfg.RequiredForGithubRemotes {
		return fmt.Errorf("required GitHub Dependabot security source unavailable: %w", err)
	}
	return nil
}

type dependabotAlert struct {
	Number     int `json:"number"`
	Dependency struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
	} `json:"dependency"`
	Advisory struct {
		GHSAID   string `json:"ghsa_id"`
		CVEID    string `json:"cve_id"`
		Severity string `json:"severity"`
	} `json:"security_advisory"`
}

type globalAdvisory struct {
	GHSAID              string `json:"ghsa_id"`
	Severity            string `json:"severity"`
	FirstPatchedVersion struct {
		Identifier string `json:"identifier"`
	} `json:"first_patched_version"`
}

func (c Client) dependabotAlerts(ctx context.Context, cfg config.GithubAdvisoriesConfig, owner, repo string) ([]dependabotAlert, error) {
	endpoint, err := apiURL(cfg.APIURL, "repos", owner, repo, "dependabot", "alerts")
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("state", "open")
	q.Set("per_page", "100")
	endpoint.RawQuery = q.Encode()

	var all []dependabotAlert
	for endpoint != nil {
		var page []dependabotAlert
		next, err := c.getJSON(ctx, cfg, endpoint, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		endpoint = next
	}
	return all, nil
}

func (c Client) advisory(ctx context.Context, cfg config.GithubAdvisoriesConfig, ghsaID string) (globalAdvisory, error) {
	if ghsaID == "" {
		return globalAdvisory{}, fmt.Errorf("missing GHSA identifier")
	}
	endpoint, err := apiURL(cfg.APIURL, "advisories", ghsaID)
	if err != nil {
		return globalAdvisory{}, err
	}
	var advisory globalAdvisory
	if _, err := c.getJSON(ctx, cfg, endpoint, &advisory); err != nil {
		return globalAdvisory{}, err
	}
	return advisory, nil
}

func (c Client) getJSON(ctx context.Context, cfg config.GithubAdvisoriesConfig, endpoint *url.URL, target any) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build GitHub read-only request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if cfg.TokenEnv != "" {
		if token := os.Getenv(cfg.TokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub read-only request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub read-only request returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return nil, fmt.Errorf("parse GitHub response: %w", err)
	}
	return nextPage(resp.Header.Get("Link")), nil
}

func apiURL(base string, parts ...string) (*url.URL, error) {
	if base == "" {
		base = "https://api.github.com"
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid GitHub API URL")
	}
	segments := []string{strings.TrimSuffix(u.Path, "/")}
	for _, part := range parts {
		segments = append(segments, url.PathEscape(part))
	}
	u.Path = path.Join(segments...)
	return u, nil
}

var githubRemotePattern = regexp.MustCompile(`(?i)^(?:https?://github\.com/|git@github\.com:)([^/]+)/([^/#]+?)(?:\.git)?$`)

func githubRepository(remote string) (owner, repo string, ok bool) {
	matches := githubRemotePattern.FindStringSubmatch(strings.TrimSpace(remote))
	if matches == nil {
		return "", "", false
	}
	return matches[1], matches[2], true
}

func nextPage(link string) *url.URL {
	for _, entry := range strings.Split(link, ",") {
		if !strings.Contains(entry, `rel="next"`) {
			continue
		}
		start, end := strings.Index(entry, "<"), strings.Index(entry, ">")
		if start < 0 || end <= start+1 {
			return nil
		}
		u, err := url.Parse(entry[start+1 : end])
		if err == nil {
			return u
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
