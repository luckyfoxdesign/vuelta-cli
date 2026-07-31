package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerReloadSwitchesExactUpstream(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("blue"))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("green"))
	}))
	defer second.Close()

	handler, err := NewHandler(Config{Listen: ":8000", Upstream: first.URL})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/hello", nil))
	if response.Body.String() != "blue" {
		t.Fatalf("first response = %q", response.Body.String())
	}
	if err := handler.Reload(Config{Listen: ":8000", Upstream: second.URL}); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/hello", nil))
	if response.Body.String() != "green" {
		t.Fatalf("second response = %q", response.Body.String())
	}
}

func TestConfigRejectsCredentialsTLSAndPaths(t *testing.T) {
	for _, upstream := range []string{
		"https://api:8000",
		"http://user:pass@api:8000",
		"http://api:8000/path",
		"http://api",
		"http://api;evil:8000",
	} {
		if err := (Config{Listen: ":8000", Upstream: upstream}).Validate(); err == nil {
			t.Fatalf("unsafe upstream accepted: %s", upstream)
		}
	}
}
