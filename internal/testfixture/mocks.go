// Package testfixture provides deterministic, network-free project fixtures
// and external-service stand-ins for integration and acceptance tests.
package testfixture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// GitHubAlertsHandler is a read-only deterministic stand-in for the two
// GitHub endpoints used by githubalerts.Client. When RequireToken is true it
// accepts only the configured bearer token and never records its value.
type GitHubAlertsHandler struct {
	RequireToken bool
	Token        string
}

func (h GitHubAlertsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.RequireToken && r.Header.Get("Authorization") != "Bearer "+h.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/repos/acme/widget/dependabot/alerts":
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		if page == "" {
			w.Header().Set("Link", fmt.Sprintf("<%s/repos/acme/widget/dependabot/alerts?page=2>; rel=\"next\"", requestOrigin(r)))
			writeJSON(w, []map[string]any{alert(1, "fixture-alpha", "GHSA-aaaa-bbbb-cccc")})
			return
		}
		if page == "2" {
			writeJSON(w, []map[string]any{alert(2, "fixture-beta", "GHSA-dddd-eeee-ffff")})
			return
		}
	case "/advisories/GHSA-aaaa-bbbb-cccc":
		writeJSON(w, map[string]any{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "severity": "high", "first_patched_version": map[string]string{"identifier": "1.2.3"}})
		return
	case "/advisories/GHSA-dddd-eeee-ffff":
		writeJSON(w, map[string]any{"ghsa_id": "GHSA-dddd-eeee-ffff", "severity": "critical", "first_patched_version": map[string]string{"identifier": "4.5.6"}})
		return
	}
	http.NotFound(w, r)
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func alert(number int, packageName, ghsa string) map[string]any {
	return map[string]any{
		"number":            number,
		"dependency":        map[string]any{"package": map[string]string{"name": packageName}, "manifest_path": "fixture.lock", "scope": "runtime"},
		"security_advisory": map[string]string{"ghsa_id": ghsa, "severity": "high"},
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	_ = json.NewEncoder(w).Encode(value)
}

// Registry is an in-memory immutable-digest registry stand-in. SetTag models
// a mutable tag changing after a candidate has already captured its digest.
type Registry struct {
	mu   sync.RWMutex
	tags map[string]string
}

func NewRegistry(tags map[string]string) *Registry {
	copyTags := make(map[string]string, len(tags))
	for tag, digest := range tags {
		copyTags[tag] = digest
	}
	return &Registry{tags: copyTags}
}

func (r *Registry) Resolve(_ context.Context, ref string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	digest, ok := r.tags[ref]
	if !ok {
		return "", fmt.Errorf("fixture registry: image %q not found", ref)
	}
	return digest, nil
}

func (r *Registry) SetTag(ref, digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[ref] = digest
}
