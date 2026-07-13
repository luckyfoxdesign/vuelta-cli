// Package logging writes local, structured operational and audit logs without
// accepting configuration secrets or forwarding log content to notifiers.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultMaxBytes int64 = 10 << 20

// Logger writes human-readable or JSON records to stdout and a private local
// state file. Callers must pass only already-redacted fields.
type Logger struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	json     bool
	stdout   io.Writer
	now      func() time.Time
}

// New opens the default state log. It creates the directory as 0700 and the
// log file as 0600, repairing overly broad permissions for existing paths.
func New(jsonLogs bool) (*Logger, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	return NewAt(filepath.Join(dir, ".local", "state", "vuelta", "vuelta.log"), defaultMaxBytes, jsonLogs, os.Stdout)
}

// NewAt is provided for tests and callers with an explicit state location.
func NewAt(path string, maxBytes int64, jsonLogs bool, stdout io.Writer) (*Logger, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if stdout == nil {
		stdout = io.Discard
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("restrict log file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close log file: %w", err)
	}
	return &Logger{path: path, maxBytes: maxBytes, json: jsonLogs, stdout: stdout, now: time.Now}, nil
}

// Event writes an INFO, WARN, or ERROR record. Keys are sorted for stable,
// readable logs; values must be secret-free summaries.
func (l *Logger) Event(level, message string, fields map[string]string) error {
	return l.write(level, message, fields)
}

// Audit writes an explicit audit record for a project pipeline outcome.
func (l *Logger) Audit(record AuditRecord) error {
	fields := map[string]string{
		"project": record.Project, "base_sha": record.BaseSHA, "commit_sha": record.CommitSHA,
		"changed_paths": strings.Join(record.ChangedPaths, ","),
		"pre_security":  strings.Join(record.PreSecurity, ","),
		"post_security": strings.Join(record.PostSecurity, ","),
		"alert_ids":     strings.Join(record.AlertIDs, ","),
		"image_digest":  record.ImageDigest, "deploy_candidate_id": record.DeployCandidateID,
	}
	return l.write("INFO", "audit", fields)
}

// AuditRecord is deliberately limited to identifiers and digests; it must
// never contain test output, diffs, webhook URLs, or bot tokens.
type AuditRecord struct {
	Project           string
	BaseSHA           string
	CommitSHA         string
	ChangedPaths      []string
	PreSecurity       []string
	PostSecurity      []string
	AlertIDs          []string
	ImageDigest       string
	DeployCandidateID string
}

func (l *Logger) write(level, message string, fields map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	stamp := l.now().UTC()
	line, err := l.format(stamp, level, message, fields)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(l.stdout, line); err != nil {
		return fmt.Errorf("write stdout log: %w", err)
	}
	if err := l.rotateIfNeeded(int64(len(line))); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.WriteString(f, line); err != nil {
		return fmt.Errorf("write log file: %w", err)
	}
	return nil
}

func (l *Logger) format(stamp time.Time, level, message string, fields map[string]string) (string, error) {
	fields = sanitize(fields)
	if l.json {
		record := map[string]string{"timestamp": stamp.Format(time.RFC3339), "level": level, "message": message}
		for key, value := range fields {
			record[key] = value
		}
		encoded, err := json.Marshal(record)
		return string(encoded) + "\n", err
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-5s %s", stamp.Format(time.RFC3339), level, message)
	for _, key := range keys {
		if fields[key] != "" {
			fmt.Fprintf(&b, " %s=%q", key, fields[key])
		}
	}
	b.WriteByte('\n')
	return b.String(), nil
}

func sanitize(fields map[string]string) map[string]string {
	clean := make(map[string]string, len(fields))
	for key, value := range fields {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "webhook") || strings.Contains(lower, "authorization") {
			clean[key] = "<redacted>"
			continue
		}
		clean[key] = value
	}
	return clean
}

func (l *Logger) rotateIfNeeded(next int64) error {
	info, err := os.Stat(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat log file: %w", err)
	}
	if info.Size()+next <= l.maxBytes {
		return nil
	}
	rotated := l.path + ".1"
	if err := os.Rename(l.path, rotated); err != nil {
		return fmt.Errorf("rotate log file: %w", err)
	}
	return os.Chmod(rotated, 0o600)
}
