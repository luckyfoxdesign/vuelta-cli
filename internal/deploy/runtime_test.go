package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/history"
)

const (
	previousDigest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	candidateDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	runtimeCommit   = "0123456789abcdef0123456789abcdef01234567"
)

type fakeRuntimeDriver struct {
	calls       []string
	smokeFailed bool
}

func (d *fakeRuntimeDriver) Preflight(context.Context, Contract) error {
	d.calls = append(d.calls, "preflight")
	return nil
}
func (d *fakeRuntimeDriver) PullExact(context.Context, Contract, history.DeploymentRelease) (string, error) {
	d.calls = append(d.calls, "pull")
	return candidateDigest, nil
}
func (d *fakeRuntimeDriver) Current(context.Context, Contract) (RunningSlot, error) {
	d.calls = append(d.calls, "current")
	return RunningSlot{
		Name: "api", Slot: "blue", Digest: previousDigest,
		Commit: "1111111111111111111111111111111111111111", Container: "api-blue",
	}, nil
}
func (d *fakeRuntimeDriver) ChangedMigrations(context.Context, Contract, string, string) ([]string, error) {
	d.calls = append(d.calls, "migrations")
	return nil, nil
}
func (d *fakeRuntimeDriver) StartCandidate(
	_ context.Context,
	_ Contract,
	_ history.DeploymentRelease,
	slot string,
) (CandidateSlot, error) {
	d.calls = append(d.calls, "start")
	return CandidateSlot{Name: "api", Slot: slot, Digest: candidateDigest, Container: "api-green"}, nil
}
func (d *fakeRuntimeDriver) WaitHealthy(context.Context, Contract, CandidateSlot) error {
	d.calls = append(d.calls, "health")
	return nil
}
func (d *fakeRuntimeDriver) SwitchTraffic(context.Context, Contract, RunningSlot, CandidateSlot) error {
	d.calls = append(d.calls, "switch")
	return nil
}
func (d *fakeRuntimeDriver) Smoke(_ context.Context, _ Contract, candidate CandidateSlot) error {
	d.calls = append(d.calls, "smoke:"+candidate.Container)
	if d.smokeFailed && candidate.Container == "api-green" {
		return errors.New("smoke failed")
	}
	return nil
}
func (d *fakeRuntimeDriver) RestoreTraffic(context.Context, Contract, RunningSlot) error {
	d.calls = append(d.calls, "restore")
	return nil
}
func (d *fakeRuntimeDriver) ActivateCompanions(
	context.Context,
	Contract,
	history.DeploymentRelease,
	CandidateSlot,
) error {
	d.calls = append(d.calls, "companions")
	return nil
}
func (d *fakeRuntimeDriver) Drain(context.Context, Contract, RunningSlot, time.Duration) error {
	d.calls = append(d.calls, "drain")
	return nil
}
func (d *fakeRuntimeDriver) Stop(context.Context, Contract, RunningSlot) error {
	d.calls = append(d.calls, "stop")
	return nil
}
func (d *fakeRuntimeDriver) RemoveCandidate(context.Context, Contract, CandidateSlot) error {
	d.calls = append(d.calls, "remove")
	return nil
}

func TestRuntimeDeploysHealthyCandidateAndStopsPrevious(t *testing.T) {
	runtime, release, contract, driver := runtimeFixture(t)
	deployed, err := runtime.Deploy(context.Background(), contract, release, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if deployed.State != "deployed" || deployed.CandidateSlot != "green" ||
		deployed.CandidateDigest != candidateDigest || deployed.PreviousDigest != previousDigest {
		t.Fatalf("deployed = %#v", deployed)
	}
	for _, expected := range []string{"preflight", "current", "pull", "migrations", "start", "health", "switch", "drain", "stop"} {
		if !slices.Contains(driver.calls, expected) {
			t.Fatalf("calls %#v missing %s", driver.calls, expected)
		}
	}
	if slices.Contains(driver.calls, "remove") {
		t.Fatalf("successful candidate was removed: %#v", driver.calls)
	}
}

func TestRuntimeRestoresPreviousSlotWhenPublicSmokeFails(t *testing.T) {
	runtime, release, contract, driver := runtimeFixture(t)
	driver.smokeFailed = true
	rolledBack, err := runtime.Deploy(context.Background(), contract, release, time.Now().UTC())
	if err == nil {
		t.Fatal("expected smoke failure")
	}
	if rolledBack.State != "rolled_back" {
		t.Fatalf("release = %#v", rolledBack)
	}
	for _, expected := range []string{"restore", "smoke:api-blue", "remove"} {
		if !slices.Contains(driver.calls, expected) {
			t.Fatalf("calls %#v missing %s", driver.calls, expected)
		}
	}
}

func runtimeFixture(t *testing.T) (*Runtime, history.DeploymentRelease, Contract, *fakeRuntimeDriver) {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := history.Open(context.Background(), filepath.Join(parent, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	release, err := store.CreateDeploymentRelease(context.Background(), history.DeploymentRelease{
		ProjectName: "api", ProjectRoot: "/projects/api",
		ReleaseRepository: "example/control", ReleaseWorkflow: "release.yml",
		SourceRepository: "example/api", SourceCommit: runtimeCommit,
		ImageRepository: "ghcr.io/example/api", ContractFingerprint: "contract",
		State: "ready", RequestedAt: now, UpdatedAt: now,
	}, history.OperationEvent{
		Type: "release_ready", Summary: "api release ready",
		IdempotencyKey: "release-ready",
	})
	if err != nil {
		t.Fatal(err)
	}
	driver := &fakeRuntimeDriver{}
	return &Runtime{
			Driver: driver, Store: store, LockPath: filepath.Join(parent, "deploy.lock"),
			DrainTimeout: time.Millisecond,
		}, release, Contract{
			Project: "api", Root: "/projects/api", TrafficService: "api",
			InternalPort: 8000, Fingerprint: "contract",
		}, driver
}
