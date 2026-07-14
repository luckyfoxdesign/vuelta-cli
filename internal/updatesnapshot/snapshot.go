// Package updatesnapshot stores short-lived, read-only package update plans.
// A snapshot deliberately contains only metadata and candidate versions; it
// never stores project file contents, command output, or configuration secrets.
package updatesnapshot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
)

var (
	ErrNotFound = errors.New("update snapshot not found")
	ErrExpired  = errors.New("update snapshot has expired; run package scan again")
	ErrInvalid  = errors.New("update snapshot is invalid")
	ErrStale    = errors.New("update snapshot is no longer current; run package scan again")
)

const FormatVersion = 1

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// Candidate is one dependency or image version chosen by a read-only scan.
// Values are metadata only and are never interpreted as a shell command.
type Candidate struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Current string `json:"current"`
	Target  string `json:"target"`
	File    string `json:"file,omitempty"`
}

// WorkspaceIdentity binds a plan to exactly one clean workspace revision and
// its explicitly allowed update inputs.
type WorkspaceIdentity struct {
	CanonicalPath string            `json:"canonical_path"`
	Remote        string            `json:"remote"`
	BaseRevision  string            `json:"base_revision"`
	InputHashes   map[string]string `json:"input_hashes"`
}

// Snapshot is the on-disk plan. It is intentionally a small, strict schema.
type Snapshot struct {
	Format     int               `json:"format"`
	ID         string            `json:"id"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Workspace  WorkspaceIdentity `json:"workspace"`
	PolicyHash string            `json:"policy_hash"`
	Candidates []Candidate       `json:"candidates"`
}

// New creates an opaque-ID snapshot. ttl must be positive and is validated by
// config before this point.
func New(now time.Time, ttl time.Duration, identity WorkspaceIdentity, policyHash string, candidates []Candidate) (Snapshot, error) {
	if ttl <= 0 {
		return Snapshot{}, fmt.Errorf("%w: non-positive ttl", ErrInvalid)
	}
	if policyHash == "" || identity.CanonicalPath == "" || identity.BaseRevision == "" {
		return Snapshot{}, fmt.Errorf("%w: incomplete workspace identity", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return Snapshot{}, err
	}
	copyCandidates := append([]Candidate(nil), candidates...)
	return Snapshot{Format: FormatVersion, ID: id, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl), Workspace: identity, PolicyHash: policyHash, Candidates: copyCandidates}, nil
}

func newID() (string, error) {
	data := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", fmt.Errorf("generate snapshot ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Store persists snapshots under a caller-selected private state directory.
type Store struct{ Dir string }

func (s Store) Save(snapshot Snapshot) error {
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	if err := ensureDir(s.Dir); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("marshal update snapshot: %w", err)
	}
	tmp, err := os.CreateTemp(s.Dir, ".snapshot-*")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	tmpName := tmp.Name()
	defer removeTemporary(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict temporary snapshot: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary snapshot: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary snapshot: %w", err)
	}
	// Link is atomic and, unlike Rename, never replaces a pre-existing ID.
	if err := os.Link(tmpName, s.path(snapshot.ID)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: generated ID collision", ErrInvalid)
		}
		return fmt.Errorf("publish update snapshot: %w", err)
	}
	return nil
}

func removeTemporary(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}

func (s Store) Load(id string) (Snapshot, error) {
	if !idPattern.MatchString(id) {
		return Snapshot{}, fmt.Errorf("%w: malformed snapshot ID", ErrInvalid)
	}
	if err := ensureDir(s.Dir); err != nil {
		return Snapshot{}, err
	}
	path := s.path(id)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("stat update snapshot: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Snapshot{}, fmt.Errorf("%w: snapshot file is not a regular file", ErrInvalid)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read update snapshot: %w", err)
	}
	var snapshot Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: parse snapshot: %v", ErrInvalid, err)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s Store) path(id string) string { return filepath.Join(s.Dir, id+".json") }

// ValidateForWorkspace rejects expired, reconfigured, dirty, rebased, or
// changed-input plans before a sandbox or package manager is started.
func ValidateForWorkspace(ctx context.Context, snapshot Snapshot, cfg config.Config, ws config.Workspace, now time.Time) error {
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	if !now.Before(snapshot.ExpiresAt) {
		return ErrExpired
	}
	policyHash, err := cfg.SnapshotPolicyHash(ws)
	if err != nil {
		return fmt.Errorf("compute snapshot policy: %w", err)
	}
	if policyHash != snapshot.PolicyHash {
		return fmt.Errorf("%w: update policy or workspace configuration changed", ErrStale)
	}
	identity, err := scanner.IdentityForSnapshot(ctx, ws)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStale, err)
	}
	actual := WorkspaceIdentity{CanonicalPath: identity.CanonicalPath, Remote: identity.Remote, BaseRevision: identity.BaseRevision, InputHashes: identity.InputHashes}
	if !reflect.DeepEqual(snapshot.Workspace, actual) {
		return fmt.Errorf("%w: workspace revision, remote, or update inputs changed", ErrStale)
	}
	return nil
}

func ensureDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: state directory must be absolute", ErrInvalid)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create snapshot state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat snapshot state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: state directory is not a real directory", ErrInvalid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: state directory permissions must not allow group or other access", ErrInvalid)
	}
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Format != FormatVersion || !idPattern.MatchString(snapshot.ID) || snapshot.CreatedAt.IsZero() || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.CreatedAt) {
		return fmt.Errorf("%w: malformed snapshot metadata", ErrInvalid)
	}
	if snapshot.Workspace.CanonicalPath == "" || snapshot.Workspace.BaseRevision == "" || snapshot.PolicyHash == "" || len(snapshot.Workspace.InputHashes) == 0 {
		return fmt.Errorf("%w: incomplete snapshot identity", ErrInvalid)
	}
	for path, sum := range snapshot.Workspace.InputHashes {
		if path == "" || filepath.IsAbs(path) || sum == "" {
			return fmt.Errorf("%w: malformed input hash", ErrInvalid)
		}
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.Kind == "" || candidate.Name == "" || candidate.Target == "" {
			return fmt.Errorf("%w: malformed candidate", ErrInvalid)
		}
		if filepath.IsAbs(candidate.File) || candidate.File == ".." || strings.HasPrefix(filepath.Clean(candidate.File), ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: candidate file escapes the workspace", ErrInvalid)
		}
	}
	return nil
}
