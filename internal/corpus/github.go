package corpus

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	defaultGitHubAPI  = "https://api.github.com"
	maxGitHubResponse = 2 << 20
	maxDiscoveryItems = 30
	maxRepositoryKB   = 50 * 1024
)

var nonSlugCharacter = regexp.MustCompile(`[^a-z0-9]+`)

// GitHubClient performs anonymous, origin-locked metadata requests. It never
// reads tokens or repository file contents.
type GitHubClient struct {
	HTTP    *http.Client
	BaseURL string
	Now     func() time.Time
}

type githubSearchResponse struct {
	Items []githubRepository `json:"items"`
}

type githubRepository struct {
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Size          int    `json:"size"`
	Archived      bool   `json:"archived"`
	License       *struct {
		SPDXID string `json:"spdx_id"`
	} `json:"license"`
}

type githubCommit struct {
	SHA string `json:"sha"`
}

type discoverySlot struct {
	manager string
	stack   string
	query   string
}

// Discover returns up to five exact-commit cases after inspecting at most 30
// repository search results. Missing GitHub access is warning-only.
func (c GitHubClient) Discover(ctx context.Context) ([]Case, []string) {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	slots := discoverySlots(now)
	seen := make(map[string]bool)
	var cases []Case
	var warnings []string
	inspected := 0
	for _, slot := range slots {
		if inspected >= maxDiscoveryItems {
			break
		}
		var response githubSearchResponse
		query := url.Values{
			"q":        []string{slot.query},
			"sort":     []string{"updated"},
			"order":    []string{"desc"},
			"per_page": []string{"6"},
		}
		if err := c.getJSON(ctx, "/search/repositories?"+query.Encode(), &response); err != nil {
			warnings = append(warnings, fmt.Sprintf("GitHub discovery for %s unavailable: %s", slot.manager, SanitizeMessage(err.Error())))
			continue
		}
		found := false
		for _, repository := range response.Items {
			if inspected >= maxDiscoveryItems {
				break
			}
			inspected++
			if seen[repository.FullName] || repository.Archived || repository.Size <= 0 || repository.Size > maxRepositoryKB ||
				repository.License == nil || !slices.Contains(allowedLicenses, repository.License.SPDXID) ||
				!validRepositoryName(repository.FullName) {
				continue
			}
			if ok := c.hasManagerMarkers(ctx, repository, slot.manager); !ok {
				continue
			}
			commit, err := c.latestCommit(ctx, repository.FullName, repository.DefaultBranch)
			if err != nil {
				continue
			}
			corpusCase := discoveryCase(repository, commit, slot)
			if err := corpusCase.validate(false); err != nil {
				continue
			}
			cases = append(cases, corpusCase)
			seen[repository.FullName] = true
			found = true
			break
		}
		if !found {
			warnings = append(warnings, fmt.Sprintf("GitHub discovery found no eligible %s project within the bounded candidate set", slot.manager))
		}
	}
	if len(cases) < 5 {
		warnings = append(warnings, fmt.Sprintf("GitHub discovery selected %d of 5 requested projects after inspecting %d of 30 candidates", len(cases), inspected))
	}
	return cases, uniqueSorted(warnings)
}

func discoverySlots(now time.Time) []discoverySlot {
	pairs := [][2]string{{"poetry", "uv"}, {"pip-tools", "requirements"}, {"uv", "pip-tools"}}
	pair := pairs[(now.YearDay()-1)%len(pairs)]
	managers := []string{"npm", "pnpm", "bun", pair[0], pair[1]}
	slots := make([]discoverySlot, 0, len(managers))
	for _, manager := range managers {
		stack := "node"
		language := "JavaScript"
		topic := manager
		if manager == "npm" {
			topic = "npm"
		}
		if slices.Contains([]string{"poetry", "uv", "pip-tools", "requirements"}, manager) {
			stack = "python"
			language = "Python"
		}
		if manager == "requirements" {
			topic = "python"
		}
		slots = append(slots, discoverySlot{
			manager: manager, stack: stack,
			query: fmt.Sprintf("topic:%s language:%s archived:false size:<%d", topic, language, maxRepositoryKB),
		})
	}
	return slots
}

func (c GitHubClient) hasManagerMarkers(ctx context.Context, repository githubRepository, manager string) bool {
	required, _ := sourcePathContract(manager)
	for _, marker := range required {
		if !c.headExists(ctx, "/repos/"+repository.FullName+"/contents/"+url.PathEscape(marker)+"?ref="+url.QueryEscape(repository.DefaultBranch)) {
			return false
		}
	}
	return true
}

func (c GitHubClient) headExists(ctx context.Context, endpoint string) bool {
	request, err := c.request(ctx, http.MethodHead, endpoint)
	if err != nil {
		return false
	}
	response, err := c.client().Do(request)
	if err != nil {
		return false
	}
	_ = response.Body.Close()
	return response.StatusCode == http.StatusOK
}

// LatestCommit resolves the default branch head for one canonical GitHub URL.
func (c GitHubClient) LatestCommit(ctx context.Context, rawURL string) (string, error) {
	if err := ValidateGitHubURL(rawURL); err != nil {
		return "", err
	}
	parsed, _ := url.Parse(rawURL)
	fullName := strings.TrimPrefix(parsed.Path, "/")
	var repository githubRepository
	if err := c.getJSON(ctx, "/repos/"+fullName, &repository); err != nil {
		return "", err
	}
	if repository.FullName != fullName || repository.DefaultBranch == "" {
		return "", errors.New("GitHub repository metadata did not match the requested project")
	}
	return c.latestCommit(ctx, fullName, repository.DefaultBranch)
}

func (c GitHubClient) latestCommit(ctx context.Context, fullName, branch string) (string, error) {
	if !validRepositoryName(fullName) || branch == "" || strings.ContainsAny(branch, "\x00\r\n") {
		return "", errors.New("GitHub repository branch metadata is invalid")
	}
	var commit githubCommit
	if err := c.getJSON(ctx, "/repos/"+fullName+"/commits/"+url.PathEscape(branch), &commit); err != nil {
		return "", err
	}
	if !fullCommitPattern.MatchString(commit.SHA) {
		return "", errors.New("GitHub returned an invalid commit identity")
	}
	return commit.SHA, nil
}

func (c GitHubClient) getJSON(ctx context.Context, endpoint string, target any) error {
	request, err := c.request(ctx, http.MethodGet, endpoint)
	if err != nil {
		return err
	}
	response, err := c.client().Do(request)
	if err != nil {
		return fmt.Errorf("request GitHub metadata: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub metadata returned HTTP %d", response.StatusCode)
	}
	reader := io.LimitReader(response.Body, maxGitHubResponse+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read GitHub metadata: %w", err)
	}
	if len(data) > maxGitHubResponse {
		return errors.New("GitHub metadata exceeded its response limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode GitHub metadata: %w", err)
	}
	return nil
}

func (c GitHubClient) request(ctx context.Context, method, endpoint string) (*http.Request, error) {
	base := c.BaseURL
	if base == "" {
		base = defaultGitHubAPI
	}
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" {
		return nil, errors.New("GitHub API origin is invalid")
	}
	if !strings.HasPrefix(endpoint, "/") || strings.HasPrefix(endpoint, "//") {
		return nil, errors.New("GitHub API endpoint is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, method, base+endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "vuelta-corpus-harness/1")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return request, nil
}

func (c GitHubClient) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("GitHub redirects are not allowed")
		},
	}
}

func discoveryCase(repository githubRepository, commit string, slot discoverySlot) Case {
	name := safeDiscoveryName(repository.FullName, slot.manager)
	expectation := Expectation{}
	if slot.manager == "bun" {
		expectation = Expectation{
			AllowedStatuses: []string{"partial"}, AllowedExits: []int{6}, AllowPartial: true,
			Capabilities: []ExpectedCapability{{
				Name: "package_updates", Status: "unavailable", ReasonContains: "scanner",
			}},
		}
	}
	return Case{
		Name: name, URL: repository.HTMLURL, Commit: commit, ExpectedStack: slot.stack,
		ExpectedPackageManager: slot.manager, ExpectedLockFormat: expectedLockFormat(slot.manager),
		License: repository.License.SPDXID, Features: []string{"discovery"},
		Scenarios: []Scenario{{Name: "default", Expect: expectation}},
	}
}

func expectedLockFormat(manager string) string {
	switch manager {
	case "npm":
		return "npm-detected"
	case "pnpm":
		return "pnpm-detected"
	case "bun":
		return "bun-text"
	case "poetry":
		return "poetry-v2"
	case "uv":
		return "uv-v1"
	case "pip-tools":
		return "requirements"
	case "requirements":
		return "requirements-direct"
	default:
		return "unknown"
	}
}

func safeDiscoveryName(fullName, manager string) string {
	value := strings.ToLower(strings.ReplaceAll(fullName, "/", "-") + "-" + manager)
	value = strings.Trim(nonSlugCharacter.ReplaceAllString(value, "-"), "-")
	if len(value) <= 64 && slugPattern.MatchString(value) {
		return value
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))[:8]
	if len(value) > 54 {
		value = strings.Trim(value[:54], "-")
	}
	return value + "-" + digest
}

func validRepositoryName(fullName string) bool {
	parts := strings.Split(fullName, "/")
	return len(parts) == 2 && githubPartPattern.MatchString(parts[0]) && githubPartPattern.MatchString(parts[1])
}

// RefreshCases resolves new default-branch commits without modifying the
// original manifest and returns a human-readable commit-only diff.
func (c GitHubClient) RefreshCases(ctx context.Context, stable []Case) ([]Case, string, error) {
	refreshed := make([]Case, 0, len(stable))
	var diff strings.Builder
	for _, corpusCase := range stable {
		commit, err := c.LatestCommit(ctx, corpusCase.URL)
		if err != nil {
			return nil, "", fmt.Errorf("refresh %s: %w", corpusCase.Name, err)
		}
		candidate := corpusCase
		candidate.Commit = commit
		if err := candidate.validate(false); err != nil {
			return nil, "", err
		}
		refreshed = append(refreshed, candidate)
		if commit != corpusCase.Commit {
			fmt.Fprintf(&diff, "%s: %s -> %s\n", corpusCase.Name, corpusCase.Commit, commit)
		} else {
			fmt.Fprintf(&diff, "%s: unchanged at %s\n", corpusCase.Name, commit)
		}
	}
	return refreshed, diff.String(), nil
}
