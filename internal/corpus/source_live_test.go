package corpus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLiveStableSources is an opt-in Docker-only attestation for pinned public
// sources. The standard test suite skips it and remains offline.
func TestLiveStableSources(t *testing.T) {
	corpusRoot := os.Getenv("VUELTA_CORPUS_LIVE_ROOT")
	if corpusRoot == "" {
		t.Skip("set VUELTA_CORPUS_LIVE_ROOT to run pinned source attestation")
	}
	if !filepath.IsAbs(corpusRoot) {
		t.Fatal("VUELTA_CORPUS_LIVE_ROOT must be absolute")
	}
	if info, err := os.Stat(corpusRoot); err != nil || !info.IsDir() {
		t.Fatal("VUELTA_CORPUS_LIVE_ROOT must be an existing directory")
	}
	manifest, err := LoadManifest(filepath.Join("..", "..", "acceptance", "corpus.example.yaml"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.ValidateStableCoverage(); err != nil {
		t.Fatal(err)
	}
	store := SourceStore{}
	for _, corpusCase := range manifest.Cases {
		t.Run(corpusCase.Name, func(t *testing.T) {
			source, err := store.Prepare(context.Background(), corpusRoot, t.TempDir(), corpusCase)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Cleanup(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
