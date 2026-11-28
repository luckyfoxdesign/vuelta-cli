package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

func TestNativeDatabaseObservations(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name, status  string
		age           time.Duration
		failDownload  bool
		failIntegrity bool
		cancelled     bool
		attempts      int
		failed        bool
	}{
		{name: "cold", status: "miss", attempts: 1},
		{name: "valid", status: "hit", age: time.Hour},
		{name: "stale refresh", status: "refreshed", age: 25 * time.Hour, attempts: 1},
		{name: "failed cold", status: "failed", failDownload: true, attempts: 3, failed: true},
		{name: "failed refresh", status: "failed", age: 25 * time.Hour, failDownload: true, attempts: 3, failed: true},
		{name: "invalid integrity", status: "failed", failIntegrity: true, attempts: 1, failed: true},
		{name: "cancelled", status: "failed", cancelled: true, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := newDatabaseLifecycle(now)
			if test.age > 0 {
				lifecycle.addDatabase(trivyDatabaseVolume(image), now.Add(-test.age))
			}
			lifecycle.failDownloads, lifecycle.failIntegrity = test.failDownload, test.failIntegrity
			scanner := lifecycle.scanner(now)
			scanner.databaseObservations = make(map[string]DatabaseCacheObservation)
			scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelled {
				cancel()
				scanner.databaseCommand = func(ctx context.Context, _ scaninput.Bundle, _ string, _ config.EgressConfig, _ string, _ bool, _ string, _ ...string) ([]byte, error) {
					return nil, ctx.Err()
				}
			}
			_, err := scanner.ensureTrivyDatabase(ctx, scaninput.Bundle{}, image, config.EgressConfig{}, 24)
			if (err != nil) != test.failed {
				t.Fatalf("error = %v", err)
			}
			observations := scanner.databaseCacheObservations()
			if len(observations) != 1 {
				t.Fatalf("observations = %+v", observations)
			}
			got := observations[0]
			if got.ScannerImage != image || len(got.CacheKey) != 16 || got.CacheStatus != test.status || got.DownloadAttempts != test.attempts || got.DownloadAttempts != lifecycle.downloads {
				t.Fatalf("observation = %+v; downloads = %d", got, lifecycle.downloads)
			}
			if !test.failed && (got.UpdatedAt == nil || !got.UpdatedAt.Equal(now.Add(-time.Hour))) {
				t.Fatalf("validated timestamp missing: %+v", got)
			}
			if test.failed && test.age == 0 && got.UpdatedAt != nil {
				t.Fatalf("unknown timestamp fabricated: %+v", got)
			}
		})
	}
}

func TestDatabaseObservationsCountRetriesAndRetainAcquisitionAcrossHits(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("b", 64)
	lifecycle := newDatabaseLifecycle(now)
	scanner := lifecycle.scanner(now)
	scanner.databaseObservations = make(map[string]DatabaseCacheObservation)
	scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
	native := scanner.databaseCommand
	attempts := 0
	scanner.databaseCommand = func(ctx context.Context, bundle scaninput.Bundle, image string, cfg config.EgressConfig, volume string, initialize bool, name string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "--download-db-only" {
			attempts++
			if attempts == 1 {
				return nil, errors.New("download vulnerability database: unexpected EOF")
			}
		}
		return native(ctx, bundle, image, cfg, volume, initialize, name, args...)
	}
	for range 2 {
		if _, err := scanner.ensureTrivyDatabase(context.Background(), scaninput.Bundle{}, image, config.EgressConfig{}, 24); err != nil {
			t.Fatal(err)
		}
	}
	got := scanner.databaseCacheObservations()
	if len(got) != 1 || got[0].CacheStatus != "miss" || got[0].DownloadAttempts != attempts || attempts != 2 {
		t.Fatalf("observations = %+v; attempts = %d", got, attempts)
	}
}

func TestDatabaseObservationsArePerScanAndSharedAcrossDistinctInputs(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	image := "scanner@sha256:" + strings.Repeat("c", 64)
	lifecycle := newDatabaseLifecycle(now)
	cfg := config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", Image: image, DatabaseMaxAgeHours: 24}}
	var first DatabaseCacheObservation
	for i := range 2 {
		root, workspace := adhocNPMWorkspace(t)
		scanner := lifecycle.scanner(now)
		scanner.allowUntrackedInputs = true
		report, err := scanner.Scan(context.Background(), root, workspace, cfg)
		if err != nil || len(report.DatabaseCaches) != 1 {
			t.Fatalf("report = %+v, error = %v", report, err)
		}
		got := report.DatabaseCaches[0]
		if i == 0 {
			first = got
			if got.CacheStatus != "miss" || got.DownloadAttempts != 1 {
				t.Fatalf("cold = %+v", got)
			}
		} else if got.CacheStatus != "hit" || got.DownloadAttempts != 0 || got.CacheKey != first.CacheKey || !got.UpdatedAt.Equal(*first.UpdatedAt) {
			t.Fatalf("second invocation = %+v; first = %+v", got, first)
		}
		// A second call on the same scanner also starts a fresh observation scope.
		again, err := scanner.Scan(context.Background(), root, workspace, cfg)
		if err != nil || len(again.DatabaseCaches) != 1 || again.DatabaseCaches[0].DownloadAttempts != 0 || again.DatabaseCaches[0].CacheStatus != "hit" {
			t.Fatalf("repeated scanner call = %+v, %v", again, err)
		}
	}
}

func TestUnavailableDatabaseObservationsStayAbsent(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	for _, failed := range []bool{false, true} {
		scanner := NewAdhocScanner(func(context.Context, string, string, ...string) ([]byte, error) {
			if failed {
				return nil, errors.New("unsupported scanner")
			}
			return []byte(trivyJSON(now.Format(time.RFC3339))), nil
		})
		scanner.Now = func() time.Time { return now }
		root, workspace := adhocNPMWorkspace(t)
		report, _ := scanner.Scan(context.Background(), root, workspace, config.Config{VulnScan: config.VulnScanConfig{DependencySource: "trivy", DatabaseMaxAgeHours: 24}})
		if len(report.DatabaseCaches) != 0 {
			t.Fatalf("unobserved scanner claimed cache evidence: %+v", report.DatabaseCaches)
		}
	}
	scanner := Scanner{databaseObservations: make(map[string]DatabaseCacheObservation)}
	for _, image := range []string{"https://operator-data@example.invalid/scanner@sha256:" + strings.Repeat("a", 64), "/private/local/scanner@sha256:" + strings.Repeat("b", 64)} {
		scanner.recordDatabaseObservation(image, "failed", time.Time{}, 0)
	}
	if len(scanner.databaseCacheObservations()) != 0 {
		t.Fatal("unsafe reference entered telemetry")
	}
}

func TestPackageDatabaseFailureRetainsNativeObservations(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	lifecycle := newDatabaseLifecycle(now)
	lifecycle.failDownloads = true
	scanner := lifecycle.scanner(now)
	scanner.allowUntrackedInputs = true
	scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
	root, workspace := adhocNPMWorkspace(t)
	report, err := scanner.Scan(context.Background(), root, workspace, config.Config{VulnScan: config.VulnScanConfig{
		DependencySource: "trivy", Image: "scanner@sha256:" + strings.Repeat("d", 64), DatabaseMaxAgeHours: 24,
	}})
	var acquisition *DatabaseAcquisitionError
	if !errors.As(err, &acquisition) || len(report.DatabaseCaches) != 1 || report.DatabaseCaches[0].CacheStatus != "failed" || report.DatabaseCaches[0].DownloadAttempts != 3 {
		t.Fatalf("failed package report = %+v, %v", report, err)
	}
}

func TestBuiltImageDatabaseObservationsSerializeOnSuccessAndFailure(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, failed := range []bool{false, true} {
		lifecycle := newDatabaseLifecycle(now)
		lifecycle.failDownloads = failed
		scanner := lifecycle.scanner(now)
		scanner.DatabaseBackoff = func(context.Context, time.Duration) error { return nil }
		native := scanner.databaseCommand
		fixture := builtFixture(t)
		scanner.databaseCommand = func(ctx context.Context, bundle scaninput.Bundle, image string, cfg config.EgressConfig, volume string, initialize bool, name string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[0] == "image" && args[1] == "--skip-db-update" {
				return []byte(fixture), nil
			}
			return native(ctx, bundle, image, cfg, volume, initialize, name, args...)
		}
		report, err := scanner.ScanBuiltImage(context.Background(), builtInput(), []string{builtRepository}, builtConfig())
		if (err != nil) != failed || len(report.DatabaseCaches) != 1 {
			t.Fatalf("report = %+v; error = %v", report, err)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var output struct {
			DatabaseCaches []DatabaseCacheObservation `json:"database_caches"`
		}
		if err := json.Unmarshal(data, &output); err != nil {
			t.Fatal(err)
		}
		got := output.DatabaseCaches[0]
		if failed {
			if got.CacheStatus != "failed" || got.DownloadAttempts != 3 || report.Status != "failed" || report.Error != "database_unavailable" {
				t.Fatalf("failed = %+v", report)
			}
		} else if got.CacheStatus != "miss" || got.DownloadAttempts != 1 || got.UpdatedAt == nil || report.Status != "findings" {
			t.Fatalf("successful = %+v", report)
		}
	}
}
