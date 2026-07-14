package githubalerts

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestScanReadsDependabotAndGlobalAdvisory(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client := Client{HTTPClient: server.Client(), RemoteURL: func(context.Context, string, string) (string, error) {
		return "git@github.com:acme/widget.git", nil
	}}
	findings, err := client.Scan(context.Background(), config.Workspace{Path: t.TempDir(), Remote: "origin"}, config.GithubAdvisoriesConfig{APIURL: server.URL})
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
