package history

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	currentSchemaVersion = 1
	maxNameBytes         = 256
	maxPathBytes         = 4096
	maxSummaryBytes      = 1024
)

// Store serializes writes through one database/sql connection. SQLite still
// uses bounded busy handling for cooperation with the future bridge process.
type Store struct {
	db   *sql.DB
	path string
}

// ResolvePath returns the configured absolute path or the protected default
// adjacent to the selected machine config.
func ResolvePath(machineConfigPath, configured string) (string, error) {
	if configured != "" {
		if !filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
			return "", errors.New("configured history database path must be clean and absolute")
		}
		return configured, nil
	}
	if machineConfigPath == "" {
		return "", errors.New("machine config path is required to resolve history database")
	}
	absolute, err := filepath.Abs(machineConfigPath)
	if err != nil {
		return "", fmt.Errorf("resolve machine config path for history: %w", err)
	}
	return filepath.Join(filepath.Dir(absolute), "state", "history.db"), nil
}

// Open validates or creates a protected database, applies explicit
// migrations, and fails closed on corruption or a newer schema.
func Open(ctx context.Context, path string) (*Store, error) {
	clean, err := preparePath(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", clean)
	if err != nil {
		return nil, fmt.Errorf("open history database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	store := &Store{db: db, path: clean}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := restrictDatabaseFiles(clean); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Path returns the canonical database path without opening any project file.
func (s *Store) Path() string { return s.path }

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func preparePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("history database path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve history database path: %w", err)
	}
	clean := filepath.Clean(absolute)
	parent := filepath.Dir(clean)
	info, err := os.Lstat(parent)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", fmt.Errorf("create history directory: %w", err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			return "", fmt.Errorf("restrict history directory: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("inspect history directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return "", errors.New("history database parent must be a real directory")
	case info.Mode().Perm()&0o077 != 0:
		return "", fmt.Errorf("history directory permissions %04o are too broad; require 0700 or stricter", info.Mode().Perm())
	}
	info, err = os.Lstat(clean)
	switch {
	case errors.Is(err, os.ErrNotExist):
		file, createErr := os.OpenFile(clean, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return "", fmt.Errorf("create history database: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return "", fmt.Errorf("close new history database: %w", closeErr)
		}
	case err != nil:
		return "", fmt.Errorf("inspect history database: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular():
		return "", errors.New("history database must be a regular non-symlink file")
	case info.Mode().Perm()&0o077 != 0:
		return "", fmt.Errorf("history database permissions %04o are too broad; require 0600 or stricter", info.Mode().Perm())
	}
	return clean, nil
}

func restrictDatabaseFiles(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		candidate := path + suffix
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite file %s: %w", filepath.Base(candidate), err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("SQLite file %s is not a regular file", filepath.Base(candidate))
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return fmt.Errorf("restrict SQLite file %s: %w", filepath.Base(candidate), err)
		}
	}
	return nil
}

func (s *Store) initialize(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure history database: %w", err)
		}
	}
	var quickCheck string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&quickCheck); err != nil {
		return fmt.Errorf("check history database integrity: %w", err)
	}
	if quickCheck != "ok" {
		return fmt.Errorf("history database integrity check failed: %s", bounded(quickCheck, maxSummaryBytes))
	}
	var userVersion int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil {
		return fmt.Errorf("read history schema version: %w", err)
	}
	if userVersion > currentSchemaVersion {
		return fmt.Errorf("history schema version %d is newer than supported version %d", userVersion, currentSchemaVersion)
	}
	if userVersion == 0 {
		if err := s.migrateV1(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrateV1(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin history schema migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range schemaV1 {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply history schema migration v1: %w", err)
		}
	}
	now := formatTime(time.Now())
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)", currentSchemaVersion, now,
	); err != nil {
		return fmt.Errorf("record history schema migration v1: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
		return fmt.Errorf("set history schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit history schema migration v1: %w", err)
	}
	return nil
}

var schemaV1 = []string{
	`CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE projects (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		root TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE scan_runs (
		id TEXT PRIMARY KEY,
		project_id INTEGER NOT NULL REFERENCES projects(id),
		base_commit TEXT NOT NULL,
		status TEXT NOT NULL CHECK(status IN ('succeeded', 'partial', 'failed')),
		started_at TEXT NOT NULL,
		completed_at TEXT NOT NULL
	) STRICT`,
	`CREATE INDEX scan_runs_project_completed ON scan_runs(project_id, completed_at DESC)`,
	`CREATE TABLE dependency_state (
		project_id INTEGER NOT NULL REFERENCES projects(id),
		ecosystem TEXT NOT NULL,
		name TEXT NOT NULL,
		is_direct INTEGER NOT NULL CHECK(is_direct IN (0, 1)),
		declared_version TEXT NOT NULL,
		resolved_version TEXT NOT NULL,
		newest_stable_version TEXT NOT NULL,
		publication_time TEXT,
		first_observed_at TEXT NOT NULL,
		eligible_at TEXT NOT NULL,
		first_seen_at TEXT NOT NULL,
		last_seen_at TEXT NOT NULL,
		version_class TEXT NOT NULL,
		disposition TEXT NOT NULL,
		PRIMARY KEY(project_id, ecosystem, name)
	) STRICT`,
	`CREATE TABLE dependency_version_events (
		id TEXT PRIMARY KEY,
		project_id INTEGER NOT NULL REFERENCES projects(id),
		scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
		ecosystem TEXT NOT NULL,
		name TEXT NOT NULL,
		from_version TEXT NOT NULL,
		to_version TEXT NOT NULL,
		observed_at TEXT NOT NULL,
		UNIQUE(scan_run_id, ecosystem, name)
	) STRICT`,
	`CREATE TABLE operations (
		id TEXT PRIMARY KEY,
		project_id INTEGER REFERENCES projects(id),
		kind TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE operation_events (
		id TEXT PRIMARY KEY,
		operation_id TEXT NOT NULL REFERENCES operations(id),
		event_type TEXT NOT NULL,
		summary TEXT NOT NULL,
		idempotency_key TEXT NOT NULL,
		created_at TEXT NOT NULL,
		UNIQUE(operation_id, idempotency_key)
	) STRICT`,
	`CREATE TABLE notification_outbox (
		id TEXT PRIMARY KEY,
		event_id TEXT NOT NULL UNIQUE REFERENCES operation_events(id),
		event_type TEXT NOT NULL,
		summary TEXT NOT NULL,
		state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'leased', 'delivered', 'failed')),
		available_at TEXT NOT NULL,
		created_at TEXT NOT NULL
	) STRICT`,
	`CREATE INDEX notification_outbox_pending ON notification_outbox(state, available_at)`,
	`CREATE TABLE update_jobs (
		id TEXT PRIMARY KEY,
		operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
		project_id INTEGER NOT NULL REFERENCES projects(id),
		repository TEXT NOT NULL,
		workflow TEXT NOT NULL,
		github_run_id INTEGER NOT NULL,
		run_url TEXT NOT NULL,
		requested_commit TEXT NOT NULL,
		status TEXT NOT NULL,
		branch TEXT NOT NULL DEFAULT '',
		pull_request_url TEXT NOT NULL DEFAULT '',
		requested_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE(repository, github_run_id)
	) STRICT`,
	`CREATE INDEX update_jobs_project_updated ON update_jobs(project_id, updated_at DESC)`,
	`CREATE TABLE approval_requests (
		id TEXT PRIMARY KEY,
		operation_id TEXT NOT NULL REFERENCES operations(id),
		approval_type TEXT NOT NULL,
		subject_fingerprint TEXT NOT NULL,
		status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'expired')),
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		decided_at TEXT
	) STRICT`,
	`CREATE TABLE operator_commands (
		id TEXT PRIMARY KEY,
		command_type TEXT NOT NULL,
		project_name TEXT NOT NULL,
		subject_id TEXT NOT NULL DEFAULT '',
		idempotency_key TEXT NOT NULL UNIQUE,
		status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'rejected')),
		created_at TEXT NOT NULL,
		consumed_at TEXT
	) STRICT`,
	`CREATE INDEX operator_commands_pending ON operator_commands(status, created_at)`,
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate history ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func bounded(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func validateText(label, value string, limit int, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if len(value) > limit || bounded(value, limit) != value {
		return fmt.Errorf("%s is invalid or exceeds %d bytes", label, limit)
	}
	return nil
}
