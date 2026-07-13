package tasks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestQueueCandidateIsPrivateAndIdempotent(t *testing.T) {
	queue := filepath.Join(t.TempDir(), "state", "tasks.jsonl")
	creator := Creator{
		Config: config.DeployTaskConfig{Mode: "queue_file", QueueFile: queue},
		Now:    func() time.Time { return time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC) },
		Random: bytes.NewReader(bytes.Repeat([]byte{1}, 32)),
	}
	in := CreateInput{Project: "api-service", CommitSHA: "0123456789abcdef0123456789abcdef01234567", ImageDigest: testDigest, ManifestDigest: testDigest}
	first, created, err := creator.Create(context.Background(), in)
	if err != nil || !created {
		t.Fatalf("first Create = %#v, %v, %v", first, created, err)
	}
	second, created, err := creator.Create(context.Background(), in)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("second Create = %#v, %v, %v", second, created, err)
	}
	info, err := os.Stat(queue)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("queue mode = %04o, want 0600", info.Mode().Perm())
	}
	items, err := ListPending(queue)
	if err != nil || len(items) != 1 || items[0].ID != first.ID {
		t.Fatalf("ListPending = %#v, %v", items, err)
	}
}

func TestCreateRejectsMutableOrInvalidIdentity(t *testing.T) {
	creator := Creator{Config: config.DeployTaskConfig{Mode: "queue_file", QueueFile: filepath.Join(t.TempDir(), "tasks.jsonl")}}
	_, _, err := creator.Create(context.Background(), CreateInput{Project: "bad/project", CommitSHA: "main", ImageDigest: "latest", ManifestDigest: "latest"})
	if err == nil {
		t.Fatal("expected invalid candidate to be rejected")
	}
}

func TestValidateCandidateRejectsUnexpectedLifecycleState(t *testing.T) {
	candidate := Candidate{
		Version: schemaVersion, ID: "0123456789abcdef0123456789abcdef", Project: "api-service",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567", ImageDigest: testDigest, ManifestDigest: testDigest,
		Timestamp: time.Now().UTC(), Status: "healthy",
	}
	if err := ValidateCandidate(candidate); err == nil {
		t.Fatal("expected non-pending candidate to be rejected")
	}
}
