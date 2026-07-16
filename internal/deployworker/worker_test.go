package deployworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/tasks"
)

const (
	testImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testManifest    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testPrevious    = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

type fakeVerifier struct{ err error }

func (v fakeVerifier) Verify(context.Context, tasks.Candidate, Project) error { return v.err }

type fakeAdapter struct {
	current        string
	ensure, deploy int
	health         int
	smoke          int
	rollback       []string
	healthErr      error
}

func (a *fakeAdapter) EnsureArtifact(context.Context, Project, string) error  { a.ensure++; return nil }
func (a *fakeAdapter) CurrentDigest(context.Context, Project) (string, error) { return a.current, nil }
func (a *fakeAdapter) Deploy(context.Context, Project, string) error          { a.deploy++; return nil }
func (a *fakeAdapter) Health(context.Context, Project) error {
	a.health++
	if a.health == 1 {
		return a.healthErr
	}
	return nil
}
func (a *fakeAdapter) Smoke(context.Context, Project) error { a.smoke++; return nil }
func (a *fakeAdapter) Rollback(_ context.Context, _ Project, digest string) error {
	a.rollback = append(a.rollback, digest)
	return nil
}

func candidate(id string) tasks.Candidate {
	return tasks.Candidate{
		Version: 1, ID: id, Project: "api", CommitSHA: "0123456789abcdef0123456789abcdef01234567",
		ImageDigest: testImageDigest, ManifestDigest: testManifest, Timestamp: time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC), Status: "pending",
	}
}

func newWorker(t *testing.T, deliveries []Delivery, adapter *fakeAdapter) Worker {
	t.Helper()
	return Worker{
		Source: StaticSource{Deliveries: deliveries}, Verifier: fakeVerifier{}, Adapter: adapter,
		Projects: map[string]Project{"api": {Name: "api", ImageRepository: "registry.example/api"}},
		StateDir: filepath.Join(t.TempDir(), "state"), MaxCandidateAge: time.Hour, Now: func() time.Time {
			return time.Date(2026, 7, 14, 0, 1, 0, 0, time.UTC)
		},
	}
}

func TestWorkerDeploysOnlyTheCandidateDigestAndRecordsPrivateState(t *testing.T) {
	adapter := &fakeAdapter{current: testPrevious}
	w := newWorker(t, []Delivery{{Candidate: candidate("11111111111111111111111111111111"), Authenticated: true}}, adapter)
	results, err := w.Run(context.Background())
	if err != nil || len(results) != 1 || results[0].Status != StatusHealthy {
		t.Fatalf("Run = %#v, %v", results, err)
	}
	if adapter.ensure != 1 || adapter.deploy != 1 || adapter.smoke != 1 || len(adapter.rollback) != 0 {
		t.Fatalf("unexpected adapter calls: %+v", adapter)
	}
	state, ok, err := w.loadState(results[0].CandidateID)
	if err != nil || !ok || state.ImageDigest != testImageDigest || state.PreviousDigest != testPrevious {
		t.Fatalf("state = %#v, %v, %v", state, ok, err)
	}
	info, err := os.Stat(w.statePath(results[0].CandidateID))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file permissions = %v, %v", info.Mode(), err)
	}
}

func TestWorkerRejectsUnauthenticatedAndDuplicateCandidatesBeforeServiceChange(t *testing.T) {
	first := candidate("22222222222222222222222222222222")
	second := candidate("33333333333333333333333333333333")
	adapter := &fakeAdapter{current: testPrevious}
	w := newWorker(t, []Delivery{{Candidate: first}, {Candidate: second, Authenticated: true}, {Candidate: second, Authenticated: true}}, adapter)
	results, err := w.Run(context.Background())
	if err != nil || len(results) != 3 {
		t.Fatalf("Run = %#v, %v", results, err)
	}
	if adapter.deploy != 1 || adapter.ensure != 1 {
		t.Fatalf("unauthenticated or repeated candidates changed the service: %+v", adapter)
	}
}

func TestWorkerRollsBackOnFailedHealthCheck(t *testing.T) {
	adapter := &fakeAdapter{current: testPrevious, healthErr: errors.New("not ready")}
	w := newWorker(t, []Delivery{{Candidate: candidate("44444444444444444444444444444444"), Authenticated: true}}, adapter)
	results, err := w.Run(context.Background())
	if err != nil || len(results) != 1 || results[0].Status != StatusRolledBack {
		t.Fatalf("Run = %#v, %v", results, err)
	}
	if len(adapter.rollback) != 1 || adapter.rollback[0] != testPrevious || adapter.health != 2 {
		t.Fatalf("rollback was not verified: %+v", adapter)
	}
}

func TestWorkerRecoversInterruptedDeploymentWithRollback(t *testing.T) {
	adapter := &fakeAdapter{current: testPrevious}
	w := newWorker(t, nil, adapter)
	state := State{CandidateID: "55555555555555555555555555555555", Project: "api", ImageDigest: testImageDigest, ManifestDigest: testManifest, PreviousDigest: testPrevious, Status: StatusRunning, UpdatedAt: w.now()}
	if err := w.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := w.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	updated, ok, err := w.loadState(state.CandidateID)
	if err != nil || !ok || updated.Status != StatusRolledBack || len(adapter.rollback) != 1 {
		t.Fatalf("recovery state = %#v, %v, %v, adapter=%+v", updated, ok, err, adapter)
	}
}

func TestWorkerHonorsProjectLock(t *testing.T) {
	adapter := &fakeAdapter{current: testPrevious}
	w := newWorker(t, []Delivery{{Candidate: candidate("66666666666666666666666666666666"), Authenticated: true}}, adapter)
	if err := w.ensureStateDir(); err != nil {
		t.Fatal(err)
	}
	unlock, err := w.lock("api")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("unlock: %v", err)
		}
	}()
	if _, err := w.Run(context.Background()); err == nil {
		t.Fatal("expected an existing project lock to stop the worker")
	}
	if adapter.deploy != 0 {
		t.Fatal("locked worker changed the service")
	}
}
