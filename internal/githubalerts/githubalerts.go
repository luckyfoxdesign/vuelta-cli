// Package githubalerts is a read-only client for GitHub Dependabot and
// Security Advisories APIs.
//
// The client sends the configured token only to the single approved HTTPS
// origin derived from the validated API base URL. Pagination must stay on
// that origin, redirects are never followed, and response size, page count,
// and decoded alert count are hard-bounded.
package githubalerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const (
	// maxPages bounds Link-header pagination per endpoint.
	maxPages = 10
	// maxResponseBytes bounds a single response body before JSON decoding.
	maxResponseBytes = 4 << 20
	// maxAlerts bounds the total number of decoded Dependabot alerts.
	maxAlerts = 1000
)

// Client makes read-only GitHub Dependabot and Global Security Advisories
// calls. Tokens are read only from an allowlisted TokenEnv variable, are sent
// only to the approved API origin, and are never included in errors, scanner
// containers, or command-line arguments.
type Client struct {
	// Transport is the injectable HTTP boundary. The client always wraps it
	// in an http.Client that refuses to follow redirects, so a
	// credential-bearing request cannot be replayed against another origin.
	Transport http.RoundTripper
	RemoteURL func(ctx context.Context, repoPath, remote string) (string, error)
}

func (c Client) httpClient() *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: c.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c Client) remoteURL(ctx context.Context, repoPath, remote string) (string, error) {
	if c.RemoteURL != nil {
		return c.RemoteURL(ctx, repoPath, remote)
	}
	if err := gitexec.ValidateRemoteName(remote); err != nil {
		return "", err
	}
	out, err := gitexec.Output(ctx, repoPath, "remote", "get-url", remote)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("get remote URL: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Scan returns open Dependabot alerts for a GitHub remote, enriched with
// Global Security Advisory data where available. It is called only when
// GitHub Dependabot is the selected dependency source, so an unsupported
// remote or any API/auth/rate-limit failure must fail closed.
func (c Client) Scan(ctx context.Context, ws config.Workspace, cfg config.GithubAdvisoriesConfig) ([]vulnscan.Finding, error) {
	origin, err := apiBase(cfg.APIURL)
	if err != nil {
		return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: %w", err)
	}
	token, err := tokenValue(cfg.TokenEnv)
	if err != nil {
		return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: %w", err)
	}
	remote, err := c.remoteURL(ctx, ws.Path, ws.Remote)
	if err != nil {
		return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: %w", err)
	}
	owner, repo, githubRemote := githubRepository(remote)
	if !githubRemote {
		return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: remote %q is not hosted by github.com", remote)
	}
	alerts, err := c.dependabotAlerts(ctx, origin, token, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: %w", err)
	}
	findings := make([]vulnscan.Finding, 0, len(alerts))
	for _, alert := range alerts {
		advisory, err := c.advisory(ctx, origin, token, alert.Advisory.GHSAID)
		if err != nil {
			return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: %w", err)
		}
		id := firstNonEmpty(advisory.GHSAID, alert.Advisory.GHSAID, alert.Advisory.CVEID)
		if id == "" || alert.Dependency.Package.Name == "" || alert.Dependency.ManifestPath == "" {
			return nil, fmt.Errorf("required GitHub Dependabot security source unavailable: dependabot alert %d has incomplete advisory or dependency data", alert.Number)
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

func (c Client) dependabotAlerts(ctx context.Context, origin *url.URL, token, owner, repo string) ([]dependabotAlert, error) {
	endpoint := apiEndpoint(origin, "repos", owner, repo, "dependabot", "alerts")
	q := endpoint.Query()
	q.Set("state", "open")
	q.Set("per_page", "100")
	endpoint.RawQuery = q.Encode()

	var all []dependabotAlert
	for page := 1; endpoint != nil; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("dependabot alert pagination exceeded %d pages", maxPages)
		}
		var alerts []dependabotAlert
		next, err := c.getJSON(ctx, origin, token, endpoint, &alerts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		if len(all) > maxAlerts {
			return nil, fmt.Errorf("dependabot alert count exceeded %d", maxAlerts)
		}
		endpoint = next
	}
	return all, nil
}

func (c Client) advisory(ctx context.Context, origin *url.URL, token, ghsaID string) (globalAdvisory, error) {
	if ghsaID == "" {
		return globalAdvisory{}, fmt.Errorf("missing GHSA identifier")
	}
	var advisory globalAdvisory
	if _, err := c.getJSON(ctx, origin, token, apiEndpoint(origin, "advisories", ghsaID), &advisory); err != nil {
		return globalAdvisory{}, err
	}
	return advisory, nil
}

func (c Client) getJSON(ctx context.Context, origin *url.URL, token string, endpoint *url.URL, target any) (*url.URL, error) {
	if err := requireSameOrigin(origin, endpoint); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build GitHub read-only request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub read-only request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub read-only request returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("GitHub response exceeded %d bytes", maxResponseBytes)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return nil, fmt.Errorf("parse GitHub response: %w", err)
	}
	return nextPage(origin, resp.Header.Get("Link"))
}

// tokenValue validates the configured token environment variable name against
// config.AllowedGithubTokenEnv and reads its value. The name allowlist keeps
// a hostile config from exfiltrating arbitrary environment credentials.
func tokenValue(tokenEnv string) (string, error) {
	if tokenEnv == "" {
		return "", nil
	}
	if !config.AllowedGithubTokenEnv(tokenEnv) {
		return "", fmt.Errorf("github_advisories.token_env: %q is not an allowed token variable (%s)", tokenEnv, strings.Join(config.GithubTokenEnvNames(), "|"))
	}
	return os.Getenv(tokenEnv), nil
}

// apiBase validates the configured API URL and returns the single approved
// origin. Errors never echo the raw configured value, which could embed
// credentials in userinfo.
func apiBase(base string) (*url.URL, error) {
	if base == "" {
		base = "https://api.github.com"
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("invalid GitHub API URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("GitHub API URL must use https")
	}
	if u.Host == "" {
		return nil, errors.New("GitHub API URL must include a host")
	}
	if u.User != nil {
		return nil, errors.New("GitHub API URL must not contain userinfo credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("GitHub API URL must not contain a query or fragment")
	}
	return u, nil
}

func apiEndpoint(origin *url.URL, parts ...string) *url.URL {
	endpoint := *origin
	segments := []string{strings.TrimSuffix(origin.Path, "/")}
	for _, part := range parts {
		segments = append(segments, url.PathEscape(part))
	}
	endpoint.Path = path.Join(segments...)
	return &endpoint
}

func requireSameOrigin(origin, endpoint *url.URL) error {
	if endpoint.Scheme != origin.Scheme || endpoint.Host != origin.Host || endpoint.User != nil {
		return fmt.Errorf("refusing GitHub request outside approved origin %s", origin.Host)
	}
	return nil
}

var githubRemotePattern = regexp.MustCompile(`(?i)^(?:https?://github\.com/|git@github\.com:)([^/]+)/([^/#]+?)(?:\.git)?$`)

func githubRepository(remote string) (owner, repo string, ok bool) {
	matches := githubRemotePattern.FindStringSubmatch(strings.TrimSpace(remote))
	if matches == nil {
		return "", "", false
	}
	return matches[1], matches[2], true
}

// nextPage parses the Link header and fails closed when a rel="next" URL is
// malformed or resolves outside the approved origin.
func nextPage(origin *url.URL, link string) (*url.URL, error) {
	for _, entry := range strings.Split(link, ",") {
		if !strings.Contains(entry, `rel="next"`) {
			continue
		}
		start, end := strings.Index(entry, "<"), strings.Index(entry, ">")
		if start < 0 || end <= start+1 {
			return nil, errors.New("malformed GitHub pagination Link header")
		}
		ref, err := url.Parse(entry[start+1 : end])
		if err != nil {
			return nil, errors.New("malformed GitHub pagination Link header")
		}
		next := origin.ResolveReference(ref)
		if err := requireSameOrigin(origin, next); err != nil {
			return nil, fmt.Errorf("pagination %w", err)
		}
		return next, nil
	}
	return nil, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
