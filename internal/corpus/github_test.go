package corpus

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubDiscoveryIsBoundedAndAnonymous(t *testing.T) {
	t.Parallel()
	commit := strings.Repeat("a", 40)
	var searches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("GitHub request included authorization")
		}
		switch {
		case strings.HasPrefix(request.URL.Path, "/search/repositories"):
			searches.Add(1)
			_, _ = fmt.Fprint(writer, `{"items":[{"full_name":"example/project","html_url":"https://github.com/example/project","default_branch":"main","size":100,"archived":false,"license":{"spdx_id":"MIT"}}]}`)
		case request.Method == http.MethodHead && strings.HasPrefix(request.URL.Path, "/repos/example/project/contents/"):
			writer.WriteHeader(http.StatusOK)
		case request.URL.Path == "/repos/example/project/commits/main":
			_, _ = fmt.Fprintf(writer, `{"sha":%q}`, commit)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := GitHubClient{BaseURL: server.URL, Now: func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}}
	cases, warnings := client.Discover(context.Background())
	if len(cases) != 1 || cases[0].Commit != commit || cases[0].ExpectedPackageManager != "npm" {
		t.Fatalf("Discover() cases = %#v", cases)
	}
	if searches.Load() != 5 {
		t.Fatalf("search requests = %d, want 5", searches.Load())
	}
	if len(warnings) == 0 {
		t.Fatal("partial discovery did not return a warning")
	}
}

func TestDiscoveryPythonPairRotates(t *testing.T) {
	t.Parallel()
	first := discoverySlots(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	second := discoverySlots(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if first[3].manager == second[3].manager && first[4].manager == second[4].manager {
		t.Fatal("Python discovery pair did not rotate")
	}
	if first[3].manager == first[4].manager {
		t.Fatal("Python discovery managers are not distinct")
	}
}

func TestRefreshCasesDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	oldCommit := strings.Repeat("a", 40)
	newCommit := strings.Repeat("b", 40)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/example/project":
			_, _ = fmt.Fprint(writer, `{"full_name":"example/project","default_branch":"main"}`)
		case "/repos/example/project/commits/main":
			_, _ = fmt.Fprintf(writer, `{"sha":%q}`, newCommit)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	original := testCase("project")
	original.URL = "https://github.com/example/project"
	original.Commit = oldCommit
	refreshed, diff, err := (GitHubClient{BaseURL: server.URL}).RefreshCases(context.Background(), []Case{original})
	if err != nil {
		t.Fatal(err)
	}
	if original.Commit != oldCommit || refreshed[0].Commit != newCommit || !strings.Contains(diff, oldCommit+" -> "+newCommit) {
		t.Fatalf("refresh = %#v, diff %q, original %s", refreshed, diff, original.Commit)
	}
}
