package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// DependencyObservation is the normalized durable state for one dependency.
type DependencyObservation struct {
	Ecosystem       string    `json:"ecosystem"`
	Name            string    `json:"name"`
	Direct          bool      `json:"direct"`
	DeclaredVersion string    `json:"declared_version"`
	ResolvedVersion string    `json:"resolved_version"`
	NewestStable    string    `json:"newest_stable_version"`
	PublicationTime time.Time `json:"publication_time,omitempty"`
	FirstObservedAt time.Time `json:"first_observed_at"`
	EligibleAt      time.Time `json:"eligible_at"`
	VersionClass    string    `json:"version_class"`
	Disposition     string    `json:"disposition"`
}

// FirstObservation returns the durable first-seen time only when the same
// newest stable version is still being observed.
func (s *Store) FirstObservation(ctx context.Context, project, ecosystem, name, newest string) (time.Time, bool, error) {
	var observed, storedNewest string
	err := s.db.QueryRowContext(ctx, `SELECT d.first_observed_at, d.newest_stable_version
		FROM dependency_state d JOIN projects p ON p.id=d.project_id
		WHERE p.name=? AND d.ecosystem=? AND d.name=?`,
		project, ecosystem, name,
	).Scan(&observed, &storedNewest)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("query dependency first observation: %w", err)
	}
	if storedNewest != newest {
		return time.Time{}, false, nil
	}
	value, err := parseTime(observed)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse dependency first observation: %w", err)
	}
	return value, true, nil
}

// ScanRecord is committed with all dependency state updates in one bounded
// writer transaction.
type ScanRecord struct {
	ID           string
	ProjectName  string
	ProjectRoot  string
	BaseCommit   string
	Status       string
	StartedAt    time.Time
	CompletedAt  time.Time
	Dependencies []DependencyObservation
}

// RecordScan inserts one run, upserts current state, and records an installed
// version event only when the resolved version actually changes.
func (s *Store) RecordScan(ctx context.Context, record ScanRecord) error {
	if record.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		record.ID = id
	}
	if err := validateScan(record); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin scan history write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := upsertProject(ctx, tx, record.ProjectName, record.ProjectRoot, record.CompletedAt)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_runs(
		id, project_id, base_commit, status, started_at, completed_at
	) VALUES(?, ?, ?, ?, ?, ?)`,
		record.ID, projectID, record.BaseCommit, record.Status,
		formatTime(record.StartedAt), formatTime(record.CompletedAt),
	); err != nil {
		return fmt.Errorf("insert scan run: %w", err)
	}
	sort.Slice(record.Dependencies, func(i, j int) bool {
		if record.Dependencies[i].Ecosystem == record.Dependencies[j].Ecosystem {
			return record.Dependencies[i].Name < record.Dependencies[j].Name
		}
		return record.Dependencies[i].Ecosystem < record.Dependencies[j].Ecosystem
	})
	for _, dependency := range record.Dependencies {
		if err := recordDependency(ctx, tx, projectID, record, dependency); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan history write: %w", err)
	}
	return nil
}

func validateScan(record ScanRecord) error {
	for label, value := range map[string]string{
		"scan ID": record.ID, "project name": record.ProjectName, "project root": record.ProjectRoot,
		"base commit": record.BaseCommit, "scan status": record.Status,
	} {
		limit := maxNameBytes
		if label == "project root" {
			limit = maxPathBytes
		}
		if err := validateText(label, value, limit, label != "base commit"); err != nil {
			return err
		}
	}
	if record.Status != "succeeded" && record.Status != "partial" && record.Status != "failed" {
		return errors.New("scan status must be succeeded, partial, or failed")
	}
	if record.StartedAt.IsZero() || record.CompletedAt.IsZero() || record.CompletedAt.Before(record.StartedAt) {
		return errors.New("scan timestamps are invalid")
	}
	if len(record.Dependencies) > 4096 {
		return errors.New("scan dependency count exceeds 4096")
	}
	return nil
}

func upsertProject(ctx context.Context, tx *sql.Tx, name, root string, now time.Time) (int64, error) {
	timestamp := formatTime(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO projects(name, root, created_at, updated_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET root=excluded.root, updated_at=excluded.updated_at`,
		name, root, timestamp, timestamp,
	); err != nil {
		return 0, fmt.Errorf("upsert history project: %w", err)
	}
	var id int64
	if err := tx.QueryRowContext(ctx, "SELECT id FROM projects WHERE name = ?", name).Scan(&id); err != nil {
		return 0, fmt.Errorf("select history project: %w", err)
	}
	return id, nil
}

func recordDependency(ctx context.Context, tx *sql.Tx, projectID int64, scan ScanRecord, dependency DependencyObservation) error {
	for label, value := range map[string]string{
		"ecosystem": dependency.Ecosystem, "dependency name": dependency.Name,
		"declared version": dependency.DeclaredVersion, "resolved version": dependency.ResolvedVersion,
		"newest stable version": dependency.NewestStable, "version class": dependency.VersionClass,
		"disposition": dependency.Disposition,
	} {
		if err := validateText(label, value, maxNameBytes, label == "ecosystem" || label == "dependency name"); err != nil {
			return err
		}
	}
	firstObserved := dependency.FirstObservedAt
	if firstObserved.IsZero() {
		firstObserved = scan.CompletedAt
	}
	eligibleAt := dependency.EligibleAt
	if eligibleAt.IsZero() {
		eligibleAt = firstObserved
	}
	var previousResolved, previousNewest, previousFirstObserved, firstSeen string
	err := tx.QueryRowContext(ctx, `SELECT resolved_version, newest_stable_version, first_observed_at, first_seen_at
		FROM dependency_state WHERE project_id=? AND ecosystem=? AND name=?`,
		projectID, dependency.Ecosystem, dependency.Name,
	).Scan(&previousResolved, &previousNewest, &previousFirstObserved, &firstSeen)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		firstSeen = formatTime(scan.CompletedAt)
	case err != nil:
		return fmt.Errorf("read dependency history state: %w", err)
	default:
		if previousNewest == dependency.NewestStable {
			firstObserved, err = parseTime(previousFirstObserved)
			if err != nil {
				return fmt.Errorf("parse dependency first observation: %w", err)
			}
			if dependency.PublicationTime.IsZero() {
				eligibleAt = firstObserved.Add(dependency.EligibleAt.Sub(dependency.FirstObservedAt))
			}
		}
		if previousResolved != "" && dependency.ResolvedVersion != "" && previousResolved != dependency.ResolvedVersion {
			eventID, idErr := newID()
			if idErr != nil {
				return idErr
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO dependency_version_events(
				id, project_id, scan_run_id, ecosystem, name, from_version, to_version, observed_at
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
				eventID, projectID, scan.ID, dependency.Ecosystem, dependency.Name,
				previousResolved, dependency.ResolvedVersion, formatTime(scan.CompletedAt),
			); err != nil {
				return fmt.Errorf("insert dependency version event: %w", err)
			}
		}
	}
	var publication any
	if !dependency.PublicationTime.IsZero() {
		publication = formatTime(dependency.PublicationTime)
	}
	direct := 0
	if dependency.Direct {
		direct = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dependency_state(
		project_id, ecosystem, name, is_direct, declared_version, resolved_version,
		newest_stable_version, publication_time, first_observed_at, eligible_at,
		first_seen_at, last_seen_at, version_class, disposition
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(project_id, ecosystem, name) DO UPDATE SET
		is_direct=excluded.is_direct,
		declared_version=excluded.declared_version,
		resolved_version=excluded.resolved_version,
		newest_stable_version=excluded.newest_stable_version,
		publication_time=excluded.publication_time,
		first_observed_at=excluded.first_observed_at,
		eligible_at=excluded.eligible_at,
		last_seen_at=excluded.last_seen_at,
		version_class=excluded.version_class,
		disposition=excluded.disposition`,
		projectID, dependency.Ecosystem, dependency.Name, direct,
		dependency.DeclaredVersion, dependency.ResolvedVersion, dependency.NewestStable,
		publication, formatTime(firstObserved), formatTime(eligibleAt),
		firstSeen, formatTime(scan.CompletedAt), dependency.VersionClass, dependency.Disposition,
	); err != nil {
		return fmt.Errorf("upsert dependency history state: %w", err)
	}
	return nil
}

// ProjectStatus is a bounded status view for humans and JSON.
type ProjectStatus struct {
	Project    string    `json:"project"`
	LastScanAt time.Time `json:"last_scan_at"`
	ScanStatus string    `json:"scan_status"`
	Routine    int       `json:"routine"`
	Deferred   int       `json:"deferred"`
}

// Status returns one row per known project.
func (s *Store) Status(ctx context.Context) ([]ProjectStatus, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.name, r.completed_at, r.status,
		COALESCE(SUM(CASE WHEN d.disposition='routine' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN d.disposition='deferred' THEN 1 ELSE 0 END), 0)
		FROM projects p
		JOIN scan_runs r ON r.id=(SELECT id FROM scan_runs WHERE project_id=p.id ORDER BY completed_at DESC, id DESC LIMIT 1)
		LEFT JOIN dependency_state d ON d.project_id=p.id
		GROUP BY p.id, p.name, r.completed_at, r.status
		ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("query project status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var output []ProjectStatus
	for rows.Next() {
		var status ProjectStatus
		var timestamp string
		if err := rows.Scan(&status.Project, &timestamp, &status.ScanStatus, &status.Routine, &status.Deferred); err != nil {
			return nil, fmt.Errorf("scan project status: %w", err)
		}
		status.LastScanAt, err = parseTime(timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse project status time: %w", err)
		}
		output = append(output, status)
	}
	return output, rows.Err()
}

// VersionEvent is one actual installed/resolved version transition.
type VersionEvent struct {
	Ecosystem  string    `json:"ecosystem"`
	Name       string    `json:"name"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	ObservedAt time.Time `json:"observed_at"`
}

// ProjectHistory returns newest-first version changes for one stable project.
func (s *Store) ProjectHistory(ctx context.Context, project string, limit int) ([]VersionEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.ecosystem, e.name, e.from_version, e.to_version, e.observed_at
		FROM dependency_version_events e
		JOIN projects p ON p.id=e.project_id
		WHERE p.name=?
		ORDER BY e.observed_at DESC, e.id DESC
		LIMIT ?`, project, limit)
	if err != nil {
		return nil, fmt.Errorf("query project history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var output []VersionEvent
	for rows.Next() {
		var event VersionEvent
		var timestamp string
		if err := rows.Scan(&event.Ecosystem, &event.Name, &event.From, &event.To, &timestamp); err != nil {
			return nil, fmt.Errorf("scan project history: %w", err)
		}
		event.ObservedAt, err = parseTime(timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse project history time: %w", err)
		}
		output = append(output, event)
	}
	return output, rows.Err()
}
