package githubalerts

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

// testToken is a fictitious credential; it must never surface in errors.
const testToken = "vuelta-fake-test-token"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(server *httptest.Server) Client {
	return Client{Transport: server.Client().Transport, RemoteURL: func(context.Context, string, string) (string, error) {
		return "git@github.com:acme/widget.git", nil
	}}
}

func testWorkspace(t *testing.T) config.Workspace {
	t.Helper()
	return config.Workspace{Path: t.TempDir(), Remote: "origin"}
}

func assertRedactedError(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaks token value: %v", err)
	}
}

func TestScanReadsDependabotAndGlobalAdvisory(t *testing.T) {
	var methods []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		switch r.URL.Path {
		case "/repos/acme/widget/dependabot/alerts":
			_, _ = fmt.Fprint(w, `[{"number":1,"dependency":{"package":{"name":"example"},"manifest_path":"go.mod","scope":"runtime"},"security_advisory":{"ghsa_id":"GHSA-1234-5678-9abc","severity":"high"}}]`)
		case "/advisories/GHSA-1234-5678-9abc":
			_, _ = fmt.Fprint(w, `{"ghsa_id":"GHSA-1234-5678-9abc","severity":"high","first_patched_version":{"identifier":"1.2.3"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	findings, err := testClient(server).Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: server.URL})
	if err != nil || len(findings) != 1 {
		t.Fatalf("Scan() = %+v, %v", findings, err)
	}
	if findings[0].ID != "GHSA-1234-5678-9abc" || findings[0].FixedVersion != "1.2.3" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("GitHub client made non-read-only request: %s", method)
		}
	}
}

func TestScanRefusesCrossOriginPagination(t *testing.T) {
	var otherRequests atomic.Int64
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherRequests.Add(1)
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer other.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/acme/widget/dependabot/alerts?page=2>; rel="next"`, other.URL))
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	t.Setenv("GITHUB_TOKEN", testToken)
	_, err := testClient(server).Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: server.URL, TokenEnv: "GITHUB_TOKEN"})
	if err == nil || !strings.Contains(err.Error(), "approved origin") {
		t.Fatalf("expected cross-origin pagination rejection, got %v", err)
	}
	if otherRequests.Load() != 0 {
		t.Fatal("cross-origin pagination server received a request")
	}
	assertRedactedError(t, err)
}

func TestScanRefusesRedirectsWithCredentials(t *testing.T) {
	var otherRequests atomic.Int64
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherRequests.Add(1)
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer other.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer server.Close()

	t.Setenv("GITHUB_TOKEN", testToken)
	_, err := testClient(server).Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: server.URL, TokenEnv: "GITHUB_TOKEN"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("expected redirect to fail closed, got %v", err)
	}
	if otherRequests.Load() != 0 {
		t.Fatal("redirect target received a request")
	}
	assertRedactedError(t, err)
}

func TestScanRejectsUnsafeAPIURLs(t *testing.T) {
	client := Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("request sent despite invalid API URL")
			return nil, nil
		}),
		RemoteURL: func(context.Context, string, string) (string, error) {
			return "git@github.com:acme/widget.git", nil
		},
	}
	cases := []struct {
		name   string
		apiURL string
	}{
		{"http downgrade", "http://api.github.com"},
		{"userinfo", "https://user:" + testToken + "@api.github.com"},
		{"missing host", "https:///repos"},
		{"query", "https://api.github.com?x=1"},
		{"unparsable", "https://api.github.com/%zz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: tc.apiURL})
			if err == nil {
				t.Fatalf("Scan accepted unsafe API URL %s", tc.name)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatalf("error leaks URL credentials: %v", err)
			}
		})
	}
}

func TestScanRejectsUnapprovedTokenEnv(t *testing.T) {
	t.Setenv("VUELTA_TEST_ARBITRARY_SECRET", testToken)
	client := Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("request sent despite unapproved token_env")
			return nil, nil
		}),
		RemoteURL: func(context.Context, string, string) (string, error) {
			return "git@github.com:acme/widget.git", nil
		},
	}
	_, err := client.Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{TokenEnv: "VUELTA_TEST_ARBITRARY_SECRET"})
	if err == nil || !strings.Contains(err.Error(), "token_env") {
		t.Fatalf("expected token_env allowlist rejection, got %v", err)
	}
	assertRedactedError(t, err)
}

func TestScanBoundsPaginationPages(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", fmt.Sprintf(`<https://%s%s?page=%d>; rel="next"`, r.Host, r.URL.Path, requests.Load()+1))
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	_, err := testClient(server).Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeded %d pages", maxPages)) {
		t.Fatalf("expected bounded pagination error, got %v", err)
	}
	if requests.Load() != maxPages {
		t.Fatalf("pagination made %d requests, want %d", requests.Load(), maxPages)
	}
}

func TestScanBoundsDecodedAlerts(t *testing.T) {
	entry := `{"number":1,"dependency":{"package":{"name":"p"},"manifest_path":"m","scope":"runtime"},"security_advisory":{"ghsa_id":"GHSA-1111-2222-3333","severity":"high"}}`
	page := "[" + strings.Repeat(entry+",", 599) + entry + "]"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<https://%s%s?page=2>; rel="next"`, r.Host, r.URL.Path))
		_, _ = fmt.Fprint(w, page)
	}))
	defer server.Close()

	_, err := testClient(server).Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeded %d", maxAlerts)) {
		t.Fatalf("expected bounded alert count error, got %v", err)
	}
}

func TestScanBoundsResponseBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "["+strings.Repeat(" ", maxResponseBytes)+"]")
	}))
	defer server.Close()

	_, err := testClient(server).Scan(context.Background(), testWorkspace(t), config.GithubAdvisoriesConfig{APIURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeded %d bytes", maxResponseBytes)) {
		t.Fatalf("expected bounded response body error, got %v", err)
	}
}
