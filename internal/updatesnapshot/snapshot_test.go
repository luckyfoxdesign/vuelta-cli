package updatesnapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func testSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snapshot, err := New(time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC), time.Hour, WorkspaceIdentity{
		CanonicalPath: "/projects/example", BaseRevision: "abc123", InputHashes: map[string]string{"package.json": "deadbeef"},
	}, "policy", []Candidate{{Kind: "npm", Name: "example", Target: "1.2.3"}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshots")
	store := Store{Dir: dir}
	want := testSnapshot(t)
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.PolicyHash != want.PolicyHash || len(got.Candidates) != 1 {
		t.Fatalf("loaded snapshot = %#v", got)
	}
	info, err := os.Stat(filepath.Join(dir, want.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestStoreRejectsTraversalAndTampering(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "snapshots")}
	if _, err := store.Load("../../outside"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("traversal error = %v, want invalid", err)
	}
	snapshot := testSnapshot(t)
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, snapshot.ID+".json"), []byte(`{"format":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(snapshot.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered load error = %v, want invalid", err)
	}
}

func TestStoreRejectsCandidateFileTraversal(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "snapshots")}
	snapshot := testSnapshot(t)
	snapshot.Candidates[0].File = "../../outside"
	if err := store.Save(snapshot); !errors.Is(err, ErrInvalid) {
		t.Fatalf("save traversal candidate error = %v, want invalid", err)
	}
}

func TestValidateForWorkspaceRejectsExpiredBeforeReadingWorkspace(t *testing.T) {
	snapshot := testSnapshot(t)
	err := ValidateForWorkspace(context.Background(), snapshot, config.Config{}, config.Workspace{}, snapshot.ExpiresAt)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("validation error = %v, want expired", err)
	}
}
