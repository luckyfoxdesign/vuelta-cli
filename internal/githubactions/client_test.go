package githubactions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"
const testRequestID = "abcdefghijklmnopqrstuv"

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{APIURL: server.URL, Token: "test-token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC) }
	client.wait = func(context.Context, time.Duration) error { return nil }
	return client
}

func TestDispatchUsesClosedInputsAndFindsExactRun(t *testing.T) {
	var dispatches, lists int
	client := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("authorization header missing")
		}
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/dispatches"):
			dispatches++
			var body struct {
				Ref    string            `json:"ref"`
				Inputs map[string]string `json:"inputs"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Ref != "main" || body.Inputs["request_id"] != testRequestID ||
				body.Inputs["cooldown_days"] != "14" || body.Inputs["include_major"] != "false" {
				t.Fatalf("dispatch body = %#v", body)
			}
			response.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/runs"):
			lists++
			if lists == 1 {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{"workflow_runs":[]}`))
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"workflow_runs":[{
				"id":123,"html_url":"https://github.com/example/api/actions/runs/123",
				"status":"queued","conclusion":"","head_sha":"` + testCommit + `",
				"head_branch":"main","display_title":"vuelta-update-` + testRequestID + `",
				"created_at":"2026-07-30T12:00:00Z","updated_at":"2026-07-30T12:00:00Z"
			}]}`))
		default:
			http.NotFound(response, request)
		}
	}))
	run, err := client.Dispatch(context.Background(), DispatchRequest{
		Repository: "example/api", Workflow: "vuelta-update.yml",
		BaseCommit: testCommit, RequestID: testRequestID, Ref: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.ID != 123 || dispatches != 1 || lists != 2 {
		t.Fatalf("run=%#v dispatches=%d lists=%d", run, dispatches, lists)
	}
}

func TestDispatchRejectsExecutableOrCrossRepositoryInput(t *testing.T) {
	client := newTestClient(t, http.NotFoundHandler())
	for _, request := range []DispatchRequest{
		{Repository: "../other", Workflow: "vuelta-update.yml", BaseCommit: testCommit, RequestID: testRequestID, Ref: "main"},
		{Repository: "example/api", Workflow: "../evil.yml", BaseCommit: testCommit, RequestID: testRequestID, Ref: "main"},
		{Repository: "example/api", Workflow: "vuelta-update.yml", BaseCommit: "main; shutdown", RequestID: testRequestID, Ref: "main"},
	} {
		if _, err := client.Dispatch(context.Background(), request); err == nil {
			t.Fatalf("unsafe request accepted: %#v", request)
		}
	}
}

func TestDispatchReleaseUsesCentralWorkflowAndClosedBuildMetadata(t *testing.T) {
	var dispatchBody struct {
		Ref    string            `json:"ref"`
		Inputs map[string]string `json:"inputs"`
	}
	client := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			if err := json.NewDecoder(request.Body).Decode(&dispatchBody); err != nil {
				t.Fatal(err)
			}
			response.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"workflow_runs":[{
				"id":321,"html_url":"https://github.com/example/control/actions/runs/321",
				"status":"queued","conclusion":"","head_sha":"` + testCommit + `",
				"head_branch":"main","display_title":"vuelta-release-` + testRequestID + `",
				"created_at":"2026-07-30T12:00:00Z","updated_at":"2026-07-30T12:00:00Z"
			}]}`))
		default:
			http.NotFound(response, request)
		}
	}))
	run, err := client.DispatchRelease(context.Background(), ReleaseDispatchRequest{
		ReleaseRepository: "example/control", Workflow: "vuelta-release.yml", Ref: "main",
		RequestID: testRequestID, SourceRepository: "example/api", SourceCommit: testCommit,
		ImageRepository: "ghcr.io/example/api", BuildContext: ".",
		Dockerfile: "docker/Dockerfile", BuildTarget: "runtime",
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.ID != 321 || dispatchBody.Inputs["source_repository"] != "example/api" ||
		dispatchBody.Inputs["dockerfile"] != "docker/Dockerfile" ||
		dispatchBody.Inputs["source_commit"] != testCommit {
		t.Fatalf("run=%#v dispatch=%#v", run, dispatchBody)
	}
}

func TestDispatchReleaseRejectsExecutablePathsAndNonGHCRImages(t *testing.T) {
	client := newTestClient(t, http.NotFoundHandler())
	base := ReleaseDispatchRequest{
		ReleaseRepository: "example/control", Workflow: "vuelta-release.yml", Ref: "main",
		RequestID: testRequestID, SourceRepository: "example/api", SourceCommit: testCommit,
		ImageRepository: "ghcr.io/example/api", BuildContext: ".",
		Dockerfile: "Dockerfile", BuildTarget: "runtime",
	}
	for _, mutate := range []func(*ReleaseDispatchRequest){
		func(request *ReleaseDispatchRequest) { request.Dockerfile = "../Dockerfile" },
		func(request *ReleaseDispatchRequest) { request.BuildTarget = "runtime;curl" },
		func(request *ReleaseDispatchRequest) { request.ImageRepository = "docker.io/example/api" },
		func(request *ReleaseDispatchRequest) { request.SourceRepository = "../api" },
	} {
		request := base
		mutate(&request)
		if _, err := client.DispatchRelease(context.Background(), request); err == nil {
			t.Fatalf("unsafe release accepted: %#v", request)
		}
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Redirect(response, &http.Request{}, "https://attacker.invalid", http.StatusFound)
	}))
	_, err := client.GetRun(context.Background(), "example/api", 42)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestClientPreservesEnterpriseAPIPathPrefix(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v3/repos/example/api/actions/runs/42" {
			t.Fatalf("request path = %q", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{
			"id":42,"html_url":"https://github.example/example/api/actions/runs/42",
			"status":"queued","conclusion":"","head_sha":"` + testCommit + `",
			"head_branch":"main","created_at":"2026-07-30T12:00:00Z",
			"updated_at":"2026-07-30T12:00:00Z"
		}`))
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{
		APIURL: server.URL + "/api/v3", Token: "test-token", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetRun(context.Background(), "example/api", 42); err != nil {
		t.Fatal(err)
	}
}

func TestClientFailureDoesNotExposeResponseBody(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte("sensitive upstream diagnostic"))
	}))
	_, err := client.GetRun(context.Background(), "example/api", 42)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("failure = %v", err)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("response body escaped into error: %v", err)
	}
}

func TestBranchHeadUsesConfiguredBranchWithoutServerFetch(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/example/api/commits" ||
			request.URL.Query().Get("sha") != "production/main" {
			t.Fatalf("request = %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[{"sha":"` + testCommit + `"}]`))
	}))
	head, err := client.BranchHead(context.Background(), "example/api", "production/main")
	if err != nil {
		t.Fatal(err)
	}
	if head != testCommit {
		t.Fatalf("head = %q", head)
	}
}
