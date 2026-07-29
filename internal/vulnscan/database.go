package vulnscan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

const (
	trivyDatabaseOwnerLabel    = "com.luckyfoxdesign.vuelta.owner"
	trivyDatabaseContractLabel = "com.luckyfoxdesign.vuelta.contract"
	trivyDatabaseOwner         = "trivy-database"
	trivyDatabaseContract      = "1"
	trivyDatabaseAttempts      = 3
)

// DatabaseFailure is a stable Trivy database acquisition failure category.
// Only FailureTransientTransport is retryable.
type DatabaseFailure string

const (
	FailureTransientTransport  DatabaseFailure = "transient_transport"
	FailureIntegrity           DatabaseFailure = "integrity"
	FailureAuthorization       DatabaseFailure = "authorization"
	FailureArtifactUnavailable DatabaseFailure = "artifact_unavailable"
	FailureInvalidDatabase     DatabaseFailure = "invalid_database"
	FailurePolicy              DatabaseFailure = "policy"
	FailureCancelled           DatabaseFailure = "cancelled"
)

// DatabaseAcquisitionError separates database availability from scanner
// execution and parsing. Error intentionally exposes only stable, bounded
// metadata; the wrapped command error remains available to hardened
// classifiers without being interpolated into user-facing text.
type DatabaseAcquisitionError struct {
	Kind             DatabaseFailure
	Attempts         int
	History          []string
	CacheStatus      string
	DatabaseAgeHours *int
	Err              error
}

func (e *DatabaseAcquisitionError) Error() string {
	if e == nil {
		return "Trivy database acquisition failed"
	}
	attempts := e.Attempts
	if attempts < 1 {
		attempts = 1
	}
	message := fmt.Sprintf("Trivy database acquisition failed: category=%s, attempts=%d", e.Kind, attempts)
	if e.CacheStatus != "" {
		message += ", cache_status=" + e.CacheStatus
	}
	if e.DatabaseAgeHours != nil {
		message += fmt.Sprintf(", database_age_hours=%d", *e.DatabaseAgeHours)
	}
	return message
}

func (e *DatabaseAcquisitionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RetryHistory returns a defensive copy of the bounded, category-only retry
// summary. It never contains registry output, proxy settings, or credentials.
func (e *DatabaseAcquisitionError) RetryHistory() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.History...)
}

type databaseSession struct {
	mu    sync.Mutex
	ready map[string]databaseCache
}

type databaseCache struct {
	volume    string
	updatedAt time.Time
}

func (s *databaseSession) readyCache(key string, maxAgeHours int, now time.Time) (databaseCache, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cache, ok := s.ready[key]
	if !ok || checkDatabaseAge(cache.updatedAt, maxAgeHours, now) != nil {
		return databaseCache{}, false
	}
	return cache, true
}

func (s *databaseSession) markReady(key string, cache databaseCache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready == nil {
		s.ready = make(map[string]databaseCache)
	}
	s.ready[key] = cache
}

func (s *databaseSession) markInvalid(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready != nil {
		delete(s.ready, key)
	}
}

func trivyDatabaseVolume(image string) string {
	sum := sha256.Sum256([]byte(image + "\x00ghcr.io/aquasecurity/trivy-db"))
	return fmt.Sprintf("vuelta-trivy-db-%x", sum[:8])
}

func trivyDatabaseVolumes(image string) [2]string {
	first := trivyDatabaseVolume(image)
	sum := sha256.Sum256([]byte(image + "\x00ghcr.io/aquasecurity/trivy-db\x00generation-2"))
	return [2]string{first, fmt.Sprintf("vuelta-trivy-db-%x", sum[:8])}
}

func (s Scanner) ensureTrivyDatabase(
	ctx context.Context,
	bundle scaninput.Bundle,
	image string,
	egressConfig config.EgressConfig,
	maxAgeHours int,
) (databaseCache, error) {
	if s.Command != nil {
		return databaseCache{}, nil
	}
	volumes := trivyDatabaseVolumes(image)
	family := volumes[0]
	if s.database != nil {
		if cache, ok := s.database.readyCache(family, maxAgeHours, s.now()); ok {
			return cache, nil
		}
	}
	lock, err := acquireDatabaseLock(ctx, family)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return databaseCache{}, ctxErr
		}
		return databaseCache{}, newDatabaseAcquisitionError(
			FailureInvalidDatabase, 1, []string{"coordination: invalid_database"}, nil, s.now(), err,
		)
	}
	defer func() { _ = lock.Close() }()
	if s.database != nil {
		if cache, ok := s.database.readyCache(family, maxAgeHours, s.now()); ok {
			return cache, nil
		}
	}
	docker := s.docker()
	for _, volume := range volumes {
		if err := ensureDatabaseVolume(ctx, docker, volume); err != nil {
			return databaseCache{}, newDatabaseAcquisitionError(
				FailureInvalidDatabase, 1, []string{"cache: invalid_database"}, nil, s.now(), err,
			)
		}
	}

	var fallback *databaseCache
	for _, volume := range volumes {
		updated, err := s.probeTrivyDatabase(ctx, bundle, image, egressConfig, volume, false)
		if err != nil {
			if isScannerPlatformMismatch(err) {
				return databaseCache{}, &ScannerPlatformError{}
			}
			if kind := classifyDatabaseFailure(err); kind != FailureInvalidDatabase {
				return databaseCache{}, newDatabaseAcquisitionError(
					kind, 1, []string{"probe: " + string(kind)}, fallback, s.now(), err,
				)
			}
			continue
		}
		cache := databaseCache{volume: volume, updatedAt: updated}
		if checkDatabaseAge(updated, maxAgeHours, s.now()) == nil {
			if s.database != nil {
				s.database.markReady(family, cache)
			}
			return cache, nil
		}
		if fallback == nil || updated.After(fallback.updatedAt) {
			copy := cache
			fallback = &copy
		}
	}

	candidate := volumes[0]
	if fallback != nil && fallback.volume == candidate {
		candidate = volumes[1]
	}
	if err := resetDatabaseVolume(ctx, docker, candidate); err != nil {
		return databaseCache{}, newDatabaseAcquisitionError(
			FailureInvalidDatabase, 1, []string{"candidate_reset: invalid_database"}, fallback, s.now(), err,
		)
	}

	history := make([]string, 0, trivyDatabaseAttempts)
	var lastErr error
	for attempt := 1; attempt <= trivyDatabaseAttempts; attempt++ {
		_, acquireErr := s.commandWithDatabase(
			ctx, bundle, image, egressConfig, candidate, true,
			"trivy", "image", "--download-db-only", "--no-progress",
		)
		var updated time.Time
		if acquireErr == nil {
			updated, acquireErr = s.probeTrivyDatabase(ctx, bundle, image, egressConfig, candidate, true)
		}
		if acquireErr == nil {
			acquireErr = checkDatabaseAge(updated, maxAgeHours, s.now())
		}
		if acquireErr == nil {
			cache := databaseCache{volume: candidate, updatedAt: updated}
			if s.database != nil {
				s.database.markReady(family, cache)
			}
			return cache, nil
		}
		lastErr = acquireErr
		kind := classifyDatabaseFailure(acquireErr)
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = cleanupDatabaseVolume(docker, candidate)
			return databaseCache{}, newDatabaseAcquisitionError(
				FailureCancelled, attempt,
				append(history, fmt.Sprintf("attempt %d: cancelled", attempt)),
				fallback, s.now(), ctxErr,
			)
		}
		if isScannerPlatformMismatch(acquireErr) {
			return databaseCache{}, &ScannerPlatformError{}
		}
		history = append(history, fmt.Sprintf("attempt %d: %s", attempt, kind))
		cleanupErr := cleanupDatabaseVolume(docker, candidate)
		if cleanupErr != nil {
			return databaseCache{}, newDatabaseAcquisitionError(
				FailureInvalidDatabase, attempt, history, fallback, s.now(), errors.Join(acquireErr, cleanupErr),
			)
		}
		if kind != FailureTransientTransport || attempt == trivyDatabaseAttempts {
			return databaseCache{}, newDatabaseAcquisitionError(
				kind, attempt, history, fallback, s.now(), acquireErr,
			)
		}
		if err := ensureDatabaseVolume(ctx, docker, candidate); err != nil {
			return databaseCache{}, newDatabaseAcquisitionError(
				FailureInvalidDatabase, attempt, history, fallback, s.now(), err,
			)
		}
		if err := s.waitForDatabaseRetry(ctx, time.Duration(attempt)*200*time.Millisecond); err != nil {
			_ = cleanupDatabaseVolume(docker, candidate)
			return databaseCache{}, newDatabaseAcquisitionError(
				FailureCancelled, attempt,
				append(history, fmt.Sprintf("backoff %d: cancelled", attempt)),
				fallback, s.now(), err,
			)
		}
	}
	return databaseCache{}, newDatabaseAcquisitionError(
		FailureTransientTransport, trivyDatabaseAttempts, history, fallback, s.now(), lastErr,
	)
}

func (s Scanner) probeTrivyDatabase(
	ctx context.Context,
	bundle scaninput.Bundle,
	image string,
	egressConfig config.EgressConfig,
	volume string,
	validateIntegrity bool,
) (time.Time, error) {
	output, err := s.commandWithDatabase(
		ctx, bundle, image, egressConfig, volume, false,
		"trivy", "version", "--format", "json",
	)
	if err != nil {
		return time.Time{}, err
	}
	updated, err := parseTrivyDatabaseVersion(output)
	if err != nil {
		return time.Time{}, err
	}
	if validateIntegrity {
		output, err = s.commandWithDatabase(
			ctx, bundle, image, egressConfig, volume, false,
			"trivy", "fs", "--skip-db-update", "--scanners", "vuln", "--format", "json", "/project",
		)
		if err != nil {
			return time.Time{}, err
		}
		if _, _, _, err := parseTrivy(output); err != nil {
			return time.Time{}, errors.New("trivy database integrity probe returned an invalid report")
		}
	}
	return updated, nil
}

func newDatabaseAcquisitionError(
	kind DatabaseFailure,
	attempts int,
	history []string,
	fallback *databaseCache,
	now time.Time,
	err error,
) *DatabaseAcquisitionError {
	result := &DatabaseAcquisitionError{
		Kind: kind, Attempts: attempts, History: history, CacheStatus: "missing", Err: err,
	}
	if fallback == nil {
		return result
	}
	age := now.Sub(fallback.updatedAt)
	if age < 0 {
		age = 0
	}
	ageHours := int(age / time.Hour)
	result.CacheStatus = "stale"
	result.DatabaseAgeHours = &ageHours
	return result
}

func parseTrivyDatabaseVersion(data []byte) (time.Time, error) {
	var document struct {
		VulnerabilityDB struct {
			Version      int    `json:"Version"`
			UpdatedAt    string `json:"UpdatedAt"`
			NextUpdate   string `json:"NextUpdate"`
			DownloadedAt string `json:"DownloadedAt"`
		} `json:"VulnerabilityDB"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return time.Time{}, errors.New("trivy database metadata is invalid")
	}
	if document.VulnerabilityDB.Version != 2 || document.VulnerabilityDB.UpdatedAt == "" ||
		document.VulnerabilityDB.DownloadedAt == "" {
		return time.Time{}, errors.New("trivy database metadata is incomplete or has an unsupported schema")
	}
	updated, err := parseTimestamp(document.VulnerabilityDB.UpdatedAt)
	if err != nil {
		return time.Time{}, errors.New("trivy database update timestamp is invalid")
	}
	downloaded, err := parseTimestamp(document.VulnerabilityDB.DownloadedAt)
	if err != nil || downloaded.Before(updated) {
		return time.Time{}, errors.New("trivy database download timestamp is invalid")
	}
	if document.VulnerabilityDB.NextUpdate != "" {
		if _, err := parseTimestamp(document.VulnerabilityDB.NextUpdate); err != nil {
			return time.Time{}, errors.New("trivy database next-update timestamp is invalid")
		}
	}
	return updated, nil
}

func (s Scanner) waitForDatabaseRetry(ctx context.Context, delay time.Duration) error {
	if s.DatabaseBackoff != nil {
		return s.DatabaseBackoff(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s Scanner) docker() dockerexec.Runner {
	if s.Docker != nil {
		return s.Docker
	}
	return dockerexec.Default()
}

func ensureDatabaseVolume(ctx context.Context, docker dockerexec.Runner, name string) error {
	result, err := docker.Run(ctx, dockerexec.Request{
		Args: []string{
			"volume", "create", "--driver", "local",
			"--label", trivyDatabaseOwnerLabel + "=" + trivyDatabaseOwner,
			"--label", trivyDatabaseContractLabel + "=" + trivyDatabaseContract,
			name,
		},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 256},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return fmt.Errorf("create Trivy database cache: %w", err)
	}
	if strings.TrimSpace(string(result.Stdout)) != name {
		return errors.New("create Trivy database cache returned an invalid name")
	}
	return verifyDatabaseVolume(ctx, docker, name)
}

func verifyDatabaseVolume(ctx context.Context, docker dockerexec.Runner, name string) error {
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"volume", "inspect", name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 16 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return fmt.Errorf("inspect Trivy database cache: %w", err)
	}
	var volumes []struct {
		Name    string            `json:"Name"`
		Driver  string            `json:"Driver"`
		Scope   string            `json:"Scope"`
		Labels  map[string]string `json:"Labels"`
		Options map[string]string `json:"Options"`
	}
	if err := json.Unmarshal(result.Stdout, &volumes); err != nil || len(volumes) != 1 {
		return errors.New("trivy database cache inspection is invalid")
	}
	volume := volumes[0]
	if volume.Name != name || volume.Driver != "local" || volume.Scope != "local" || len(volume.Options) != 0 ||
		volume.Labels[trivyDatabaseOwnerLabel] != trivyDatabaseOwner ||
		volume.Labels[trivyDatabaseContractLabel] != trivyDatabaseContract {
		return errors.New("trivy database cache ownership or storage contract is invalid")
	}
	return nil
}

func resetDatabaseVolume(ctx context.Context, docker dockerexec.Runner, name string) error {
	if err := removeDatabaseVolume(ctx, docker, name); err != nil {
		return err
	}
	return ensureDatabaseVolume(ctx, docker, name)
}

func removeDatabaseVolume(ctx context.Context, docker dockerexec.Runner, name string) error {
	if err := verifyDatabaseVolume(ctx, docker, name); err != nil {
		return err
	}
	_, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"volume", "rm", name},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return fmt.Errorf("remove incomplete Trivy database cache: %w", err)
	}
	return nil
}

func cleanupDatabaseVolume(docker dockerexec.Runner, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return removeDatabaseVolume(ctx, docker, name)
}

func (s Scanner) invalidateTrivyDatabase(family, volume string) error {
	if s.database != nil {
		s.database.markInvalid(family)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lock, err := acquireDatabaseLock(ctx, family)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	return removeDatabaseVolume(ctx, s.docker(), volume)
}

var statusCodePattern = regexp.MustCompile(`\b(401|403|404|408|429|5[0-9]{2})\b`)

func classifyDatabaseFailure(err error) DatabaseFailure {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return FailureCancelled
	}
	var policyErr *egress.StageError
	if errors.As(err, &policyErr) {
		return FailurePolicy
	}
	_, _, detail := dockerexec.Classify(err)
	if detail == "" && err != nil {
		detail = safeerr.Excerpt([]byte(err.Error()), 1024)
	}
	lower := strings.ToLower(detail)
	status := statusCodePattern.FindString(lower)
	switch {
	case strings.Contains(lower, "unauthorized"), strings.Contains(lower, "authentication required"),
		strings.Contains(lower, "access denied"), strings.Contains(lower, "forbidden"),
		status == "401", status == "403":
		return FailureAuthorization
	case strings.Contains(lower, "digest mismatch"), strings.Contains(lower, "checksum mismatch"),
		strings.Contains(lower, "integrity"), strings.Contains(lower, "failed to verify"),
		strings.Contains(lower, "signature verification"):
		return FailureIntegrity
	case strings.Contains(lower, "manifest unknown"), strings.Contains(lower, "artifact not found"),
		strings.Contains(lower, "repository not found"), status == "404":
		return FailureArtifactUnavailable
	case strings.Contains(lower, "unexpected eof"), strings.Contains(lower, "connection reset"),
		strings.Contains(lower, "connection refused"), strings.Contains(lower, "temporarily unavailable"),
		strings.Contains(lower, "i/o timeout"), strings.Contains(lower, "tls handshake timeout"),
		strings.Contains(lower, "no such host"), status == "408", status == "429",
		strings.HasPrefix(status, "5"):
		return FailureTransientTransport
	default:
		return FailureInvalidDatabase
	}
}
