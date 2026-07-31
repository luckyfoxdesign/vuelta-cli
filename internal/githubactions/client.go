// Package githubactions implements the narrow GitHub Actions API surface used
// to dispatch and inspect Vuelta update workflows.
package githubactions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxResponseBytes = 1 << 20
	policyVersion    = 1
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	workflowPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml$`)
	commitPattern     = regexp.MustCompile(`^[a-f0-9]{40}$`)
	requestIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	refPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	imagePattern      = regexp.MustCompile(`^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*$`)
	relativePattern   = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,511}$`)
)

// Client sends credentials only to one validated HTTPS API origin.
type Client struct {
	base       *url.URL
	token      string
	httpClient *http.Client
	now        func() time.Time
	wait       func(context.Context, time.Duration) error
}

// Config constructs a fail-closed client.
type Config struct {
	APIURL     string
	Token      string
	HTTPClient *http.Client
}

// New validates the fixed API origin and disables redirects.
func New(config Config) (*Client, error) {
	apiURL := strings.TrimSuffix(config.APIURL, "/")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	base, err := url.Parse(apiURL)
	testClientAllowsPort := config.HTTPClient != nil
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil ||
		(!testClientAllowsPort && base.Port() != "" && base.Port() != "443") || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("GitHub Actions API URL must be one HTTPS origin without credentials")
	}
	if config.Token == "" {
		return nil, errors.New("GitHub Actions token is required")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		base: base, token: config.Token, httpClient: &copyClient, now: time.Now,
		wait: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}, nil
}

// DispatchRequest contains identifiers and policy inputs only.
type DispatchRequest struct {
	Repository   string
	Workflow     string
	BaseCommit   string
	RequestID    string
	IncludeMajor bool
	Ref          string
}

// ReleaseDispatchRequest starts the central, Vuelta-owned release workflow.
// Build metadata is derived from an exact configured workspace and contains
// paths and identifiers only, never executable shell text or credentials.
type ReleaseDispatchRequest struct {
	ReleaseRepository string
	Workflow          string
	Ref               string
	RequestID         string
	SourceRepository  string
	SourceCommit      string
	ImageRepository   string
	BuildContext      string
	Dockerfile        string
	BuildTarget       string
}

// Run is a bounded known workflow run view.
type Run struct {
	ID         int64     `json:"id"`
	URL        string    `json:"url"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion,omitempty"`
	HeadSHA    string    `json:"head_sha"`
	HeadBranch string    `json:"head_branch,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Dispatch requests one workflow and finds the resulting run by the exact
// request-specific run name and base commit.
func (c *Client) Dispatch(ctx context.Context, request DispatchRequest) (Run, error) {
	if err := validateRequest(request); err != nil {
		return Run{}, err
	}
	started := c.now().UTC().Add(-time.Minute)
	body := struct {
		Ref    string            `json:"ref"`
		Inputs map[string]string `json:"inputs"`
	}{
		Ref: request.Ref,
		Inputs: map[string]string{
			"request_id": request.RequestID, "base_commit": request.BaseCommit,
			"policy_version": strconv.Itoa(policyVersion), "cooldown_days": "14",
			"include_major": strconv.FormatBool(request.IncludeMajor),
		},
	}
	var response struct{}
	if err := c.doJSON(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/actions/workflows/%s/dispatches", request.Repository, request.Workflow),
		body, http.StatusNoContent, &response,
	); err != nil {
		return Run{}, fmt.Errorf("dispatch GitHub update workflow: %w", err)
	}
	for attempt := 0; attempt < 10; attempt++ {
		run, found, err := c.findDispatchedRun(ctx, request, started)
		if err != nil {
			return Run{}, err
		}
		if found {
			return run, nil
		}
		if attempt < 9 {
			if err := c.wait(ctx, time.Second); err != nil {
				return Run{}, err
			}
		}
	}
	return Run{}, errors.New("GitHub accepted the dispatch but its exact run was not visible before the bounded lookup deadline")
}

// DispatchRelease requests one central release build and finds the exact run
// by its opaque request-specific title. The workflow's head SHA belongs to the
// control repository, so source identity remains a separate closed input.
func (c *Client) DispatchRelease(ctx context.Context, request ReleaseDispatchRequest) (Run, error) {
	if err := validateReleaseRequest(request); err != nil {
		return Run{}, err
	}
	started := c.now().UTC().Add(-time.Minute)
	body := struct {
		Ref    string            `json:"ref"`
		Inputs map[string]string `json:"inputs"`
	}{
		Ref: request.Ref,
		Inputs: map[string]string{
			"request_id": request.RequestID, "contract_version": strconv.Itoa(policyVersion),
			"source_repository": request.SourceRepository, "source_commit": request.SourceCommit,
			"image_repository": request.ImageRepository, "build_context": request.BuildContext,
			"dockerfile": request.Dockerfile, "build_target": request.BuildTarget,
		},
	}
	var response struct{}
	if err := c.doJSON(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/actions/workflows/%s/dispatches", request.ReleaseRepository, request.Workflow),
		body, http.StatusNoContent, &response,
	); err != nil {
		return Run{}, fmt.Errorf("dispatch GitHub release workflow: %w", err)
	}
	for attempt := 0; attempt < 10; attempt++ {
		run, found, err := c.findReleaseRun(ctx, request, started)
		if err != nil {
			return Run{}, err
		}
		if found {
			return run, nil
		}
		if attempt < 9 {
			if err := c.wait(ctx, time.Second); err != nil {
				return Run{}, err
			}
		}
	}
	return Run{}, errors.New("GitHub accepted the release dispatch but its exact run was not visible before the bounded lookup deadline")
}

func validateRequest(request DispatchRequest) error {
	switch {
	case !repositoryPattern.MatchString(request.Repository) || strings.Contains(request.Repository, ".."):
		return errors.New("GitHub repository must be one exact owner/repository identifier")
	case !workflowPattern.MatchString(request.Workflow) || strings.Contains(request.Workflow, ".."):
		return errors.New("GitHub workflow must be one YAML filename")
	case !commitPattern.MatchString(request.BaseCommit):
		return errors.New("GitHub update base commit must be a full lowercase SHA")
	case !refPattern.MatchString(request.Ref) || strings.Contains(request.Ref, "..") || strings.Contains(request.Ref, "//"):
		return errors.New("GitHub update ref is invalid")
	case !requestIDPattern.MatchString(request.RequestID):
		return errors.New("GitHub update request ID is invalid")
	default:
		return nil
	}
}

func validateReleaseRequest(request ReleaseDispatchRequest) error {
	switch {
	case !repositoryPattern.MatchString(request.ReleaseRepository) || strings.Contains(request.ReleaseRepository, ".."):
		return errors.New("GitHub release repository must be one exact owner/repository identifier")
	case !workflowPattern.MatchString(request.Workflow) || strings.Contains(request.Workflow, ".."):
		return errors.New("GitHub release workflow must be one YAML filename")
	case !refPattern.MatchString(request.Ref) || strings.Contains(request.Ref, "..") || strings.Contains(request.Ref, "//"):
		return errors.New("GitHub release workflow ref is invalid")
	case !requestIDPattern.MatchString(request.RequestID):
		return errors.New("GitHub release request ID is invalid")
	case !repositoryPattern.MatchString(request.SourceRepository) || strings.Contains(request.SourceRepository, ".."):
		return errors.New("GitHub source repository must be one exact owner/repository identifier")
	case !commitPattern.MatchString(request.SourceCommit):
		return errors.New("GitHub release source commit must be a full lowercase SHA")
	case !imagePattern.MatchString(request.ImageRepository) || strings.Contains(request.ImageRepository, ".."):
		return errors.New("GitHub release image repository must be one allowlisted GHCR path")
	case !safeRelative(request.BuildContext), !safeRelative(request.Dockerfile):
		return errors.New("GitHub release build paths must be clean project-relative paths")
	case request.BuildTarget != "" && !refPattern.MatchString(request.BuildTarget):
		return errors.New("GitHub release build target is invalid")
	default:
		return nil
	}
}

func (c *Client) findDispatchedRun(ctx context.Context, request DispatchRequest, started time.Time) (Run, bool, error) {
	query := url.Values{
		"event":    {"workflow_dispatch"},
		"head_sha": {request.BaseCommit},
		"created":  {">=" + started.Format(time.RFC3339)},
		"per_page": {"20"},
	}
	var response struct {
		Runs []struct {
			ID           int64  `json:"id"`
			HTMLURL      string `json:"html_url"`
			Status       string `json:"status"`
			Conclusion   string `json:"conclusion"`
			HeadSHA      string `json:"head_sha"`
			HeadBranch   string `json:"head_branch"`
			DisplayTitle string `json:"display_title"`
			CreatedAt    string `json:"created_at"`
			UpdatedAt    string `json:"updated_at"`
		} `json:"workflow_runs"`
	}
	path := fmt.Sprintf("/repos/%s/actions/workflows/%s/runs?%s", request.Repository, request.Workflow, query.Encode())
	if err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, &response); err != nil {
		return Run{}, false, fmt.Errorf("find dispatched GitHub update run: %w", err)
	}
	expectedTitle := "vuelta-update-" + request.RequestID
	for _, candidate := range response.Runs {
		if candidate.DisplayTitle != expectedTitle || candidate.HeadSHA != request.BaseCommit {
			continue
		}
		return parseRun(candidate.ID, candidate.HTMLURL, candidate.Status, candidate.Conclusion,
			candidate.HeadSHA, candidate.HeadBranch, candidate.CreatedAt, candidate.UpdatedAt)
	}
	return Run{}, false, nil
}

func (c *Client) findReleaseRun(
	ctx context.Context,
	request ReleaseDispatchRequest,
	started time.Time,
) (Run, bool, error) {
	query := url.Values{
		"event": {"workflow_dispatch"}, "created": {">=" + started.Format(time.RFC3339)}, "per_page": {"20"},
	}
	var response struct {
		Runs []struct {
			ID           int64  `json:"id"`
			HTMLURL      string `json:"html_url"`
			Status       string `json:"status"`
			Conclusion   string `json:"conclusion"`
			HeadSHA      string `json:"head_sha"`
			HeadBranch   string `json:"head_branch"`
			DisplayTitle string `json:"display_title"`
			CreatedAt    string `json:"created_at"`
			UpdatedAt    string `json:"updated_at"`
		} `json:"workflow_runs"`
	}
	path := fmt.Sprintf("/repos/%s/actions/workflows/%s/runs?%s",
		request.ReleaseRepository, request.Workflow, query.Encode())
	if err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, &response); err != nil {
		return Run{}, false, fmt.Errorf("find dispatched GitHub release run: %w", err)
	}
	expectedTitle := "vuelta-release-" + request.RequestID
	for _, candidate := range response.Runs {
		if candidate.DisplayTitle != expectedTitle {
			continue
		}
		return parseRun(candidate.ID, candidate.HTMLURL, candidate.Status, candidate.Conclusion,
			candidate.HeadSHA, candidate.HeadBranch, candidate.CreatedAt, candidate.UpdatedAt)
	}
	return Run{}, false, nil
}

func safeRelative(value string) bool {
	return relativePattern.MatchString(value) && value != ".." &&
		!strings.HasPrefix(value, "../") && !strings.Contains(value, "/../") &&
		!strings.Contains(value, "//")
}

// GetRun reads one already-known run ID from the same configured repository.
func (c *Client) GetRun(ctx context.Context, repository string, runID int64) (Run, error) {
	if !repositoryPattern.MatchString(repository) || runID <= 0 {
		return Run{}, errors.New("known GitHub repository and positive run ID are required")
	}
	var response struct {
		ID         int64  `json:"id"`
		HTMLURL    string `json:"html_url"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		HeadSHA    string `json:"head_sha"`
		HeadBranch string `json:"head_branch"`
		CreatedAt  string `json:"created_at"`
		UpdatedAt  string `json:"updated_at"`
	}
	if err := c.doJSON(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/actions/runs/%d", repository, runID),
		nil, http.StatusOK, &response,
	); err != nil {
		return Run{}, fmt.Errorf("read known GitHub update run: %w", err)
	}
	run, _, err := parseRun(response.ID, response.HTMLURL, response.Status, response.Conclusion,
		response.HeadSHA, response.HeadBranch, response.CreatedAt, response.UpdatedAt)
	return run, err
}

// BranchHead resolves the newest exact commit on one configured branch
// without requiring a server-side fetch or working-tree mutation.
func (c *Client) BranchHead(ctx context.Context, repository, branch string) (string, error) {
	if !repositoryPattern.MatchString(repository) || strings.Contains(repository, "..") ||
		!refPattern.MatchString(branch) || strings.Contains(branch, "..") || strings.Contains(branch, "//") {
		return "", errors.New("known GitHub repository and branch are required")
	}
	query := url.Values{"sha": {branch}, "per_page": {"1"}}
	var response []struct {
		SHA string `json:"sha"`
	}
	if err := c.doJSON(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/commits?%s", repository, query.Encode()),
		nil, http.StatusOK, &response,
	); err != nil {
		return "", fmt.Errorf("read configured GitHub branch head: %w", err)
	}
	if len(response) != 1 || !commitPattern.MatchString(response[0].SHA) {
		return "", errors.New("configured GitHub branch returned no exact commit")
	}
	return response[0].SHA, nil
}

func parseRun(id int64, htmlURL, status, conclusion, headSHA, headBranch, created, updated string) (Run, bool, error) {
	if id <= 0 || !commitPattern.MatchString(headSHA) {
		return Run{}, false, errors.New("GitHub run response has invalid identity")
	}
	runURL, err := url.Parse(htmlURL)
	if err != nil || runURL.Scheme != "https" || runURL.Hostname() == "" || runURL.User != nil {
		return Run{}, false, errors.New("GitHub run response has invalid URL")
	}
	createdAt, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return Run{}, false, errors.New("GitHub run response has invalid created_at")
	}
	updatedAt, err := time.Parse(time.RFC3339, updated)
	if err != nil {
		return Run{}, false, errors.New("GitHub run response has invalid updated_at")
	}
	return Run{
		ID: id, URL: htmlURL, Status: status, Conclusion: conclusion,
		HeadSHA: headSHA, HeadBranch: bounded(headBranch, 256),
		CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC(),
	}, true, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody any, expected int, responseBody any) error {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return err
	}
	var body io.Reader
	if requestBody != nil {
		data, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		if len(data) > 16<<10 {
			return errors.New("GitHub request exceeds bounded size")
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != expected {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	if expected == http.StatusNoContent {
		return nil
	}
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("GitHub API response exceeds bounded size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(responseBody); err != nil {
		return errors.New("GitHub API response is invalid JSON")
	}
	return nil
}

func (c *Client) endpoint(path string) (*url.URL, error) {
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(relative.Path, "/") {
		return nil, errors.New("GitHub API path is invalid")
	}
	prefix := strings.TrimSuffix(c.base.Path, "/")
	joinedPath := prefix + relative.Path
	endpoint := &url.URL{
		Scheme:   c.base.Scheme,
		Host:     c.base.Host,
		Path:     joinedPath,
		RawQuery: relative.RawQuery,
	}
	if endpoint.Scheme != c.base.Scheme || endpoint.Host != c.base.Host ||
		!strings.HasPrefix(endpoint.Path, prefix+"/") {
		return nil, errors.New("GitHub API path escaped the configured origin")
	}
	return endpoint, nil
}

func bounded(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
