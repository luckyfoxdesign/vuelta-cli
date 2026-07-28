package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

func TestTrivyDatabaseTransientTruncationRetriesThenSucceeds(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	calls := 0
	scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("download vulnerability database: unexpected EOF")
		}
		return []byte(trivyJSON(now.Format(time.RFC3339))), nil
	})
	scanner.Now = func() time.Time { return now }
	scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
	root, workspace := adhocNPMWorkspace(t)
	report, err := scanner.Scan(context.Background(), root, workspace, config.Config{
		VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24},
	})
	if err != nil || len(report.Findings) != 1 || calls != 2 {
		t.Fatalf("Scan() = %#v, %v; calls=%d", report, err, calls)
	}
}

func TestTrivyDatabaseRepeatedEOFRetainsBoundedRetryHistory(t *testing.T) {
	calls := 0
	scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("download vulnerability database: unexpected EOF")
	})
	scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
	root, workspace := adhocNPMWorkspace(t)
	_, err := scanner.Scan(context.Background(), root, workspace, config.Config{
		VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24},
	})
	var databaseErr *DatabaseAcquisitionError
	if !errors.As(err, &databaseErr) {
		t.Fatalf("Scan error = %v, want DatabaseAcquisitionError", err)
	}
	if databaseErr.Kind != FailureTransientTransport || databaseErr.Attempts != 3 || calls != 3 {
		t.Fatalf("database error = %#v; calls=%d", databaseErr, calls)
	}
	want := []string{
		"attempt 1: transient_transport",
		"attempt 2: transient_transport",
		"attempt 3: transient_transport",
	}
	if !reflect.DeepEqual(databaseErr.RetryHistory(), want) {
		t.Fatalf("retry history = %#v, want %#v", databaseErr.RetryHistory(), want)
	}
}

func TestTrivyDatabaseRetryClassification(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		wantKind DatabaseFailure
		wantCall int
	}{
		{name: "timeout", message: "download vulnerability database: i/o timeout", wantKind: FailureTransientTransport, wantCall: 3},
		{name: "authorization", message: "download vulnerability database: unauthorized: authentication required", wantKind: FailureAuthorization, wantCall: 1},
		{name: "artifact unavailable", message: "download vulnerability database: manifest unknown", wantKind: FailureArtifactUnavailable, wantCall: 1},
		{name: "digest mismatch", message: "download vulnerability database: digest mismatch", wantKind: FailureIntegrity, wantCall: 1},
		{name: "invalid metadata", message: "vulnerability database metadata.json is malformed", wantKind: FailureInvalidDatabase, wantCall: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
				calls++
				return nil, errors.New(test.message)
			})
			scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
			root, workspace := adhocNPMWorkspace(t)
			_, err := scanner.Scan(context.Background(), root, workspace, config.Config{
				VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24},
			})
			var databaseErr *DatabaseAcquisitionError
			if !errors.As(err, &databaseErr) || databaseErr.Kind != test.wantKind || calls != test.wantCall {
				t.Fatalf("error = %#v; calls=%d, want kind=%s calls=%d", databaseErr, calls, test.wantKind, test.wantCall)
			}
		})
	}
	if got := classifyDatabaseFailure(&egress.StageError{
		Stage: "network preparation", Err: errors.New("managed policy unavailable"),
	}); got != FailurePolicy {
		t.Fatalf("egress policy classification = %s, want %s", got, FailurePolicy)
	}
}

func TestTrivyDatabaseCancellationStopsBackoffAndFurtherAttempts(t *testing.T) {
	calls := 0
	scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("download vulnerability database: unexpected EOF")
	})
	scanner.DatabaseBackoff = func(context.Context, time.Duration) error {
		return context.Canceled
	}
	root, workspace := adhocNPMWorkspace(t)
	_, err := scanner.Scan(context.Background(), root, workspace, config.Config{
		VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24},
	})
	var databaseErr *DatabaseAcquisitionError
	if !errors.As(err, &databaseErr) || databaseErr.Kind != FailureCancelled || calls != 1 {
		t.Fatalf("error = %#v; calls=%d", databaseErr, calls)
	}
}

func TestParseTrivyDatabaseVersionValidatesFreshnessInputs(t *testing.T) {
	updated := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	document := `{"VulnerabilityDB":{"Version":2,"UpdatedAt":"` + updated.Format(time.RFC3339) +
		`","NextUpdate":"` + updated.Add(6*time.Hour).Format(time.RFC3339) +
		`","DownloadedAt":"` + updated.Add(time.Hour).Format(time.RFC3339) + `"}}`
	got, err := parseTrivyDatabaseVersion([]byte(document))
	if err != nil || !got.Equal(updated) {
		t.Fatalf("parseTrivyDatabaseVersion() = %v, %v", got, err)
	}
	if err := checkDatabaseAge(got, 24, updated.Add(25*time.Hour)); err == nil {
		t.Fatal("expired cached database was accepted")
	}
	for _, invalid := range []string{
		`{"VulnerabilityDB":{"Version":2}}`,
		`{"VulnerabilityDB":{"Version":1,"UpdatedAt":"2026-07-27T06:00:00Z","DownloadedAt":"2026-07-27T07:00:00Z"}}`,
		`{"VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-07-27T06:00:00Z","DownloadedAt":"2026-07-27T05:00:00Z"}}`,
	} {
		if _, err := parseTrivyDatabaseVersion([]byte(invalid)); err == nil {
			t.Fatalf("partial or invalid cache metadata was accepted: %s", invalid)
		}
	}
}

func TestReadyDatabaseSessionIsAFreshHitWithoutDockerOrDownload(t *testing.T) {
	image := "scanner@sha256:" + strings.Repeat("a", 64)
	session := &databaseSession{}
	session.markReady(trivyDatabaseVolume(image))
	scanner := Scanner{database: session, Docker: panicDocker{}}
	if err := scanner.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	); err != nil {
		t.Fatalf("fresh in-session cache hit failed: %v", err)
	}
}

func TestDatabaseVolumeResetIsOwnedAndAtomicAtTheDockerBoundary(t *testing.T) {
	docker := &databaseVolumeDocker{exists: true, labels: managedDatabaseLabels()}
	name := "vuelta-trivy-db-0123456789abcdef"
	if err := resetDatabaseVolume(context.Background(), docker, name); err != nil {
		t.Fatal(err)
	}
	want := []string{"inspect", "rm", "create", "inspect"}
	if !reflect.DeepEqual(docker.operations, want) {
		t.Fatalf("volume operations = %#v, want %#v", docker.operations, want)
	}
	if !docker.exists || !reflect.DeepEqual(docker.labels, managedDatabaseLabels()) {
		t.Fatalf("replacement cache = exists:%t labels:%#v", docker.exists, docker.labels)
	}
}

func TestDatabaseVolumeNeverRemovesForeignCollision(t *testing.T) {
	docker := &databaseVolumeDocker{
		exists: true,
		labels: map[string]string{trivyDatabaseOwnerLabel: "foreign"},
	}
	name := "vuelta-trivy-db-0123456789abcdef"
	if err := resetDatabaseVolume(context.Background(), docker, name); err == nil {
		t.Fatal("foreign cache collision was reset")
	}
	if contains(docker.operations, "rm") {
		t.Fatalf("foreign cache was removed: %#v", docker.operations)
	}
}

func TestDatabaseAcquisitionLockCoordinatesConcurrentScans(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed scanner cache is unsupported on Windows")
	}
	name := "vuelta-trivy-db-fedcba9876543210"
	first, err := acquireDatabaseLock(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan databaseLock, 1)
	failures := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		lock, lockErr := acquireDatabaseLock(ctx, name)
		if lockErr != nil {
			failures <- lockErr
			return
		}
		acquired <- lock
	}()
	select {
	case lock := <-acquired:
		_ = lock.Close()
		t.Fatal("second acquisition did not wait for the first")
	case err := <-failures:
		t.Fatalf("second acquisition failed early: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case lock := <-acquired:
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-failures:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

type panicDocker struct{}

func (panicDocker) Path() (string, error) { panic("unexpected Docker call") }
func (panicDocker) Run(context.Context, dockerexec.Request) (dockerexec.Result, error) {
	panic("unexpected Docker call")
}

type databaseVolumeDocker struct {
	mu         sync.Mutex
	exists     bool
	labels     map[string]string
	operations []string
}

func (*databaseVolumeDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *databaseVolumeDocker) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(request.Args) < 2 || request.Args[0] != "volume" {
		return dockerexec.Result{}, errors.New("unexpected Docker request")
	}
	operation := request.Args[1]
	d.operations = append(d.operations, operation)
	name := request.Args[len(request.Args)-1]
	switch operation {
	case "create":
		if !d.exists {
			d.exists = true
			d.labels = managedDatabaseLabels()
		}
		return dockerexec.Result{Stdout: []byte(name + "\n")}, nil
	case "inspect":
		if !d.exists {
			return dockerexec.Result{}, errors.New("volume does not exist")
		}
		data, err := json.Marshal([]any{map[string]any{
			"Name": name, "Driver": "local", "Scope": "local",
			"Labels": d.labels, "Options": map[string]string{},
		}})
		return dockerexec.Result{Stdout: data}, err
	case "rm":
		if !d.exists {
			return dockerexec.Result{}, errors.New("volume does not exist")
		}
		d.exists = false
		d.labels = nil
		return dockerexec.Result{}, nil
	default:
		return dockerexec.Result{}, errors.New("unexpected volume operation")
	}
}

func managedDatabaseLabels() map[string]string {
	return map[string]string{
		trivyDatabaseOwnerLabel:    trivyDatabaseOwner,
		trivyDatabaseContractLabel: trivyDatabaseContract,
	}
}
