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

func TestTrivyScannerPlatformMismatchIsNotDatabaseFailure(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{name: "runtime architecture", message: "standard_init_linux.go: exec user process caused: exec format error"},
		{
			name:    "missing platform manifest",
			message: "no matching manifest for linux/amd64 in the manifest list entries",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
				calls++
				return nil, errors.New(test.message)
			})
			root, workspace := adhocNPMWorkspace(t)
			_, err := scanner.Scan(context.Background(), root, workspace, config.Config{
				VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24},
			})
			var platformErr *ScannerPlatformError
			if !errors.As(err, &platformErr) || calls != 1 {
				t.Fatalf("error = %v; calls=%d, want ScannerPlatformError after one call", err, calls)
			}
			var databaseErr *DatabaseAcquisitionError
			if errors.As(err, &databaseErr) {
				t.Fatalf("platform mismatch was reported as database failure: %#v", databaseErr)
			}
			if strings.Contains(err.Error(), test.message) {
				t.Fatalf("public error exposed raw platform diagnostic: %q", err)
			}
		})
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
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	session := &databaseSession{}
	session.markReady(trivyDatabaseVolume(image), databaseCache{
		volume: trivyDatabaseVolume(image), updatedAt: now.Add(-time.Hour),
	})
	scanner := Scanner{database: session, Docker: panicDocker{}, Now: func() time.Time { return now }}
	cache, err := scanner.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	if err != nil {
		t.Fatalf("fresh in-session cache hit failed: %v", err)
	}
	if cache.volume != trivyDatabaseVolume(image) {
		t.Fatalf("cache volume = %q", cache.volume)
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

func TestFreshDatabaseCacheAvoidsDownloadAcrossScannerSessions(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("a", 64)
	volumes := trivyDatabaseVolumes(image)
	lifecycle := newDatabaseLifecycle(now)
	lifecycle.addDatabase(volumes[0], now.Add(-time.Hour))

	first := lifecycle.scanner(now)
	cache, err := first.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	if err != nil || cache.volume != volumes[0] {
		t.Fatalf("first cache selection = %#v, %v", cache, err)
	}
	second := lifecycle.scanner(now)
	cache, err = second.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	if err != nil || cache.volume != volumes[0] {
		t.Fatalf("second cache selection = %#v, %v", cache, err)
	}
	if lifecycle.downloads != 0 {
		t.Fatalf("fresh cache triggered %d downloads", lifecycle.downloads)
	}
}

func TestScannerPlatformMismatchPreservesExistingDatabaseVolume(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("7", 64)
	volumes := trivyDatabaseVolumes(image)
	lifecycle := newDatabaseLifecycle(now)
	updated := now.Add(-time.Hour)
	lifecycle.addDatabase(volumes[0], updated)

	scanner := lifecycle.scanner(now)
	scanner.databaseCommand = func(
		context.Context,
		scaninput.Bundle,
		string,
		config.EgressConfig,
		string,
		bool,
		string,
		...string,
	) ([]byte, error) {
		return nil, errors.New("exec format error: scanner@sha256:untrusted")
	}
	_, err := scanner.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	var platformErr *ScannerPlatformError
	if !errors.As(err, &platformErr) {
		t.Fatalf("error = %v, want ScannerPlatformError", err)
	}
	if got, ok := lifecycle.databaseUpdated(volumes[0]); !ok || !got.Equal(updated) {
		t.Fatalf("platform mismatch changed valid database volume: %v, exists=%t", got, ok)
	}
	if lifecycle.downloads != 0 {
		t.Fatalf("platform mismatch attempted %d database downloads", lifecycle.downloads)
	}
}

func TestExpiredDatabaseRefreshesInactiveGenerationBeforeActivation(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("b", 64)
	volumes := trivyDatabaseVolumes(image)
	lifecycle := newDatabaseLifecycle(now)
	staleUpdated := now.Add(-25 * time.Hour)
	lifecycle.addDatabase(volumes[0], staleUpdated)

	scanner := lifecycle.scanner(now)
	cache, err := scanner.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	if err != nil {
		t.Fatal(err)
	}
	if cache.volume != volumes[1] || lifecycle.downloads != 1 || lifecycle.integrityProbes != 1 {
		t.Fatalf(
			"refresh result = volume:%q downloads:%d integrity_probes:%d",
			cache.volume, lifecycle.downloads, lifecycle.integrityProbes,
		)
	}
	if got, ok := lifecycle.databaseUpdated(volumes[0]); !ok || !got.Equal(staleUpdated) {
		t.Fatalf("last known-good generation was changed: %v, exists=%t", got, ok)
	}

	second := lifecycle.scanner(now)
	secondCache, err := second.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	if err != nil || secondCache.volume != volumes[1] || lifecycle.downloads != 1 {
		t.Fatalf(
			"post-refresh cache hit = %#v, %v; downloads=%d",
			secondCache, err, lifecycle.downloads,
		)
	}
}

func TestFailedDatabaseRefreshPreservesStaleGenerationAndReportsAge(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("c", 64)
	volumes := trivyDatabaseVolumes(image)
	lifecycle := newDatabaseLifecycle(now)
	staleUpdated := now.Add(-31 * time.Hour)
	lifecycle.addDatabase(volumes[0], staleUpdated)
	lifecycle.failDownloads = true

	scanner := lifecycle.scanner(now)
	scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
	_, err := scanner.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	var databaseErr *DatabaseAcquisitionError
	if !errors.As(err, &databaseErr) {
		t.Fatalf("refresh error = %v, want DatabaseAcquisitionError", err)
	}
	if databaseErr.Kind != FailureTransientTransport ||
		databaseErr.CacheStatus != "stale" ||
		databaseErr.DatabaseAgeHours == nil ||
		*databaseErr.DatabaseAgeHours != 31 ||
		lifecycle.downloads != trivyDatabaseAttempts {
		t.Fatalf("refresh error = %#v; downloads=%d", databaseErr, lifecycle.downloads)
	}
	if got, ok := lifecycle.databaseUpdated(volumes[0]); !ok || !got.Equal(staleUpdated) {
		t.Fatalf("failed refresh destroyed last known-good generation: %v, exists=%t", got, ok)
	}
	if _, ok := lifecycle.databaseUpdated(volumes[1]); ok {
		t.Fatal("failed candidate generation remained active")
	}
}

func TestInvalidRefreshedDatabaseNeverBecomesActive(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("9", 64)
	volumes := trivyDatabaseVolumes(image)
	lifecycle := newDatabaseLifecycle(now)
	staleUpdated := now.Add(-26 * time.Hour)
	lifecycle.addDatabase(volumes[0], staleUpdated)
	lifecycle.failIntegrity = true

	scanner := lifecycle.scanner(now)
	_, err := scanner.ensureTrivyDatabase(
		context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
	)
	var databaseErr *DatabaseAcquisitionError
	if !errors.As(err, &databaseErr) ||
		databaseErr.Kind != FailureIntegrity ||
		databaseErr.CacheStatus != "stale" {
		t.Fatalf("integrity failure = %#v", databaseErr)
	}
	if got, ok := lifecycle.databaseUpdated(volumes[0]); !ok || !got.Equal(staleUpdated) {
		t.Fatalf("integrity failure changed last known-good generation: %v, exists=%t", got, ok)
	}
	if _, ok := lifecycle.databaseUpdated(volumes[1]); ok {
		t.Fatal("unvalidated candidate generation remained active")
	}
}

func TestConcurrentDatabaseRefreshDownloadsOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed scanner cache is unsupported on Windows")
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("d", 64)
	lifecycle := newDatabaseLifecycle(now)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			scanner := lifecycle.scanner(now)
			_, err := scanner.ensureTrivyDatabase(
				context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
			)
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if lifecycle.downloads != 1 {
		t.Fatalf("concurrent refresh performed %d downloads", lifecycle.downloads)
	}
}

func TestChangingScannerDigestUsesASeparateDatabaseGeneration(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	firstImage := "scanner@sha256:" + strings.Repeat("e", 64)
	secondImage := "scanner@sha256:" + strings.Repeat("f", 64)
	if trivyDatabaseVolumes(firstImage) == trivyDatabaseVolumes(secondImage) {
		t.Fatal("different scanner digests share database generations")
	}
	lifecycle := newDatabaseLifecycle(now)
	for _, image := range []string{firstImage, secondImage} {
		scanner := lifecycle.scanner(now)
		if _, err := scanner.ensureTrivyDatabase(
			context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24,
		); err != nil {
			t.Fatal(err)
		}
	}
	if lifecycle.downloads != 2 {
		t.Fatalf("two scanner digests performed %d database downloads", lifecycle.downloads)
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

type databaseLifecycle struct {
	mu              sync.Mutex
	now             time.Time
	volumes         map[string]map[string]string
	updated         map[string]time.Time
	downloads       int
	integrityProbes int
	failDownloads   bool
	failIntegrity   bool
}

func newDatabaseLifecycle(now time.Time) *databaseLifecycle {
	return &databaseLifecycle{
		now: now, volumes: make(map[string]map[string]string), updated: make(map[string]time.Time),
	}
}

func (d *databaseLifecycle) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *databaseLifecycle) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(request.Args) < 2 || request.Args[0] != "volume" {
		return dockerexec.Result{}, errors.New("unexpected Docker request")
	}
	name := request.Args[len(request.Args)-1]
	switch request.Args[1] {
	case "create":
		if _, ok := d.volumes[name]; !ok {
			d.volumes[name] = managedDatabaseLabels()
		}
		return dockerexec.Result{Stdout: []byte(name + "\n")}, nil
	case "inspect":
		labels, ok := d.volumes[name]
		if !ok {
			return dockerexec.Result{}, errors.New("volume does not exist")
		}
		data, err := json.Marshal([]any{map[string]any{
			"Name": name, "Driver": "local", "Scope": "local",
			"Labels": labels, "Options": map[string]string{},
		}})
		return dockerexec.Result{Stdout: data}, err
	case "rm":
		if _, ok := d.volumes[name]; !ok {
			return dockerexec.Result{}, errors.New("volume does not exist")
		}
		delete(d.volumes, name)
		delete(d.updated, name)
		return dockerexec.Result{}, nil
	default:
		return dockerexec.Result{}, errors.New("unexpected volume operation")
	}
}

func (d *databaseLifecycle) scanner(now time.Time) Scanner {
	return Scanner{
		Docker: d, database: &databaseSession{}, Now: func() time.Time { return now },
		databaseCommand: func(
			_ context.Context,
			_ scaninput.Bundle,
			_ string,
			_ config.EgressConfig,
			volume string,
			_ bool,
			_ string,
			args ...string,
		) ([]byte, error) {
			d.mu.Lock()
			defer d.mu.Unlock()
			if len(args) >= 2 && args[0] == "image" && args[1] == "--download-db-only" {
				d.downloads++
				if d.failDownloads {
					return nil, errors.New("download vulnerability database: unexpected EOF")
				}
				d.updated[volume] = d.now.Add(-time.Hour)
				return nil, nil
			}
			if len(args) >= 1 && args[0] == "version" {
				updated, ok := d.updated[volume]
				if !ok {
					return nil, errors.New("vulnerability database metadata.json is missing")
				}
				return trivyDatabaseVersionJSON(updated), nil
			}
			if len(args) >= 1 && args[0] == "fs" {
				if _, ok := d.updated[volume]; !ok {
					return nil, errors.New("vulnerability database is missing")
				}
				d.integrityProbes++
				if d.failIntegrity {
					return nil, errors.New("vulnerability database integrity checksum mismatch")
				}
				return []byte(`{"Results":[]}`), nil
			}
			return nil, errors.New("unexpected Trivy database command")
		},
	}
}

func (d *databaseLifecycle) addDatabase(volume string, updated time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.volumes[volume] = managedDatabaseLabels()
	d.updated[volume] = updated
}

func (d *databaseLifecycle) databaseUpdated(volume string) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	updated, ok := d.updated[volume]
	return updated, ok
}

func trivyDatabaseVersionJSON(updated time.Time) []byte {
	return []byte(`{"VulnerabilityDB":{"Version":2,"UpdatedAt":"` +
		updated.Format(time.RFC3339) + `","NextUpdate":"` +
		updated.Add(6*time.Hour).Format(time.RFC3339) + `","DownloadedAt":"` +
		updated.Add(time.Hour).Format(time.RFC3339) + `"}}`)
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
