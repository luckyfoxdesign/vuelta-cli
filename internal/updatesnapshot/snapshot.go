// Package updatesnapshot stores short-lived, read-only package update plans.
// A snapshot deliberately contains only metadata and candidate versions; it
// never stores project file contents, command output, or configuration secrets.
package updatesnapshot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	ErrExpired  = errors.New("update snapshot has expired; rerun vuelta scan")
	ErrInvalid  = errors.New("update snapshot is invalid")
	ErrStale    = errors.New("update snapshot is no longer current; rerun vuelta scan")
)

const (
	// FormatVersion is intentionally incompatible with the short-lived format
	// 1 plans. Format 2 records the scan origin and every security-relevant
	// scan-time input needed by the explicit scan -> update workflow.
	FormatVersion = 2

	OriginWorkspace = "workspace"
	OriginAdhoc     = "adhoc"
	PolicyNone      = "none"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
var candidatePartPattern = regexp.MustCompile(`^[A-Za-z0-9@._+:/-]+$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Candidate is one dependency or image version chosen by a read-only scan.
// Values are metadata only and are never interpreted as a shell command.
type Candidate struct {
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	Current            string `json:"current"`
	Target             string `json:"target"`
	File               string `json:"file,omitempty"`
	ReleaseAgeVerified bool   `json:"release_age_verified"`
}

// WorkspaceIdentity binds a plan to exactly one clean workspace revision and
// its explicitly allowed update inputs.
type WorkspaceIdentity struct {
	CanonicalPath string            `json:"canonical_path"`
	Remote        string            `json:"remote"`
	BaseRevision  string            `json:"base_revision"`
	InputHashes   map[string]string `json:"input_hashes"`
}

// PolicyIdentity records an optional, canonical standalone policy. The
// explicit "none" sentinel prevents an omitted policy from being confused
// with a producer that forgot to record it.
type PolicyIdentity struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

// ScanGates records security decisions made while candidates were selected.
type ScanGates struct {
	AllowProjectConfig bool   `json:"allow_project_config"`
	MinReleaseAge      string `json:"min_release_age"`
}

// Snapshot is the on-disk plan. It is intentionally a small, strict schema.
type Snapshot struct {
	Format      int               `json:"format"`
	ID          string            `json:"id"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Origin      string            `json:"origin"`
	Project     string            `json:"project,omitempty"`
	AdhocPath   string            `json:"adhoc_path,omitempty"`
	Workspace   WorkspaceIdentity `json:"workspace,omitempty"`
	InputHashes map[string]string `json:"input_hashes,omitempty"`
	Policy      PolicyIdentity    `json:"policy"`
	Gates       ScanGates         `json:"scan_gates"`
	ConfigHash  string            `json:"config_hash,omitempty"`
	PolicyHash  string            `json:"policy_hash"`
	Candidates  []Candidate       `json:"candidates"`
}

// New creates an opaque-ID snapshot. ttl must be positive and is validated by
// config before this point.
func New(now time.Time, ttl time.Duration, identity WorkspaceIdentity, policyHash string, candidates []Candidate) (Snapshot, error) {
	policy := PolicyIdentity{Path: PolicyNone, Hash: PolicyNone}
	gates := ScanGates{MinReleaseAge: "0s"}
	effectiveHash, err := EffectivePolicyHash(policyHash, policy, gates)
	if err != nil {
		return Snapshot{}, err
	}
	return NewWorkspace(now, ttl, filepath.Base(identity.CanonicalPath), identity, policy, gates, policyHash, effectiveHash, candidates)
}

// NewWorkspace creates a format-2 plan bound to a registered workspace.
func NewWorkspace(now time.Time, ttl time.Duration, project string, identity WorkspaceIdentity, policy PolicyIdentity, gates ScanGates, configHash, effectivePolicyHash string, candidates []Candidate) (Snapshot, error) {
	id, err := newID()
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		Format: FormatVersion, ID: id, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
		Origin: OriginWorkspace, Project: project, Workspace: identity, Policy: policy,
		Gates: gates, ConfigHash: configHash, PolicyHash: effectivePolicyHash,
		Candidates: append([]Candidate(nil), candidates...),
	}
	if ttl <= 0 {
		return Snapshot{}, fmt.Errorf("%w: non-positive ttl", ErrInvalid)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// NewAdhoc creates a format-2 plan bound to an explicit unregistered path.
func NewAdhoc(now time.Time, ttl time.Duration, canonicalPath string, inputHashes map[string]string, policy PolicyIdentity, gates ScanGates, effectivePolicyHash string, candidates []Candidate) (Snapshot, error) {
	id, err := newID()
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		Format: FormatVersion, ID: id, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
		Origin: OriginAdhoc, AdhocPath: canonicalPath, InputHashes: cloneHashes(inputHashes),
		Policy: policy, Gates: gates, PolicyHash: effectivePolicyHash,
		Candidates: append([]Candidate(nil), candidates...),
	}
	if ttl <= 0 {
		return Snapshot{}, fmt.Errorf("%w: non-positive ttl", ErrInvalid)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func cloneHashes(hashes map[string]string) map[string]string {
	copyHashes := make(map[string]string, len(hashes))
	for path, hash := range hashes {
		copyHashes[path] = hash
	}
	return copyHashes
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
	if err := validateExistingDir(s.Dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
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
	if snapshot.Format == 1 {
		return Snapshot{}, fmt.Errorf("%w: snapshot format 1 is no longer supported; rerun vuelta scan", ErrInvalid)
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
	if snapshot.Origin != OriginWorkspace || snapshot.Project != config.WorkspaceName(ws) {
		return fmt.Errorf("%w: snapshot origin or project changed", ErrStale)
	}
	policyHash, err := cfg.SnapshotPolicyHash(ws)
	if err != nil {
		return fmt.Errorf("compute snapshot policy: %w", err)
	}
	if policyHash != snapshot.ConfigHash {
		return fmt.Errorf("%w: update policy or workspace configuration changed", ErrStale)
	}
	if err := validatePolicyIdentity(snapshot.Policy); err != nil {
		return err
	}
	effectiveHash, err := EffectivePolicyHash(snapshot.ConfigHash, snapshot.Policy, snapshot.Gates)
	if err != nil || effectiveHash != snapshot.PolicyHash {
		return fmt.Errorf("%w: effective scan policy changed", ErrStale)
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

// ValidateForAdhoc rejects an expired snapshot when the explicit directory,
// its manifest/lock inputs, or its standalone policy changed.
func ValidateForAdhoc(snapshot Snapshot, canonicalPath string, inputHashes map[string]string, now time.Time) error {
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	if !now.Before(snapshot.ExpiresAt) {
		return ErrExpired
	}
	if snapshot.Origin != OriginAdhoc || snapshot.AdhocPath != canonicalPath || !reflect.DeepEqual(snapshot.InputHashes, inputHashes) {
		return fmt.Errorf("%w: adhoc target or update inputs changed", ErrStale)
	}
	if err := validatePolicyIdentity(snapshot.Policy); err != nil {
		return err
	}
	effectiveHash, err := EffectivePolicyHash("adhoc", snapshot.Policy, snapshot.Gates)
	if err != nil || effectiveHash != snapshot.PolicyHash {
		return fmt.Errorf("%w: effective scan policy changed", ErrStale)
	}
	return nil
}

// EffectivePolicyHash binds the selected configuration, standalone policy,
// and scan-time gates into one deterministic identity.
func EffectivePolicyHash(configHash string, policy PolicyIdentity, gates ScanGates) (string, error) {
	data, err := json.Marshal(struct {
		ConfigHash string
		Policy     PolicyIdentity
		Gates      ScanGates
	}{configHash, policy, gates})
	if err != nil {
		return "", fmt.Errorf("encode effective scan policy: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// ValidateCandidates rejects malformed, duplicated, unsupported, or
// unverified candidates before an environment check or mutable action starts.
func ValidateCandidates(snapshot Snapshot, allowUnverifiedReleaseAge bool) error {
	if len(snapshot.Candidates) == 0 {
		return fmt.Errorf("%w: snapshot has no update candidates", ErrInvalid)
	}
	allowedKinds := map[string]bool{
		"poetry": true, "uv": true, "pip-tools": true,
		"npm": true, "pnpm": true, "bun": true, "docker": true,
	}
	seen := make(map[string]bool, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if !allowedKinds[candidate.Kind] || !candidatePartPattern.MatchString(candidate.Name) ||
			!candidatePartPattern.MatchString(candidate.Target) || strings.HasPrefix(candidate.Name, "-") ||
			strings.HasPrefix(candidate.Target, "-") ||
			(candidate.Current != "" && !candidatePartPattern.MatchString(candidate.Current)) {
			return fmt.Errorf("%w: inadmissible candidate %s/%s", ErrInvalid, candidate.Kind, candidate.Name)
		}
		if (candidate.Kind == "docker") != (candidate.File != "") {
			return fmt.Errorf("%w: candidate %s has an invalid file binding", ErrInvalid, candidate.Name)
		}
		key := candidate.Kind + "\x00" + candidate.Name + "\x00" + candidate.File
		if seen[key] {
			return fmt.Errorf("%w: duplicate candidate %s/%s", ErrInvalid, candidate.Kind, candidate.Name)
		}
		seen[key] = true
		if !candidate.ReleaseAgeVerified && !allowUnverifiedReleaseAge {
			return fmt.Errorf("%w: candidate %s has unverified release age; rerun with --allow-unverified-release-age only after review", ErrInvalid, candidate.Name)
		}
	}
	return nil
}

func validatePolicyIdentity(policy PolicyIdentity) error {
	if policy.Path == PolicyNone {
		if policy.Hash != PolicyNone {
			return fmt.Errorf("%w: malformed absent-policy sentinel", ErrInvalid)
		}
		return nil
	}
	info, err := os.Lstat(policy.Path)
	if err != nil {
		return fmt.Errorf("%w: stat policy: %v", ErrStale, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: policy is not a regular file", ErrStale)
	}
	canonical, err := filepath.EvalSymlinks(policy.Path)
	if err != nil || canonical != policy.Path {
		return fmt.Errorf("%w: policy path is no longer canonical", ErrStale)
	}
	data, err := os.ReadFile(policy.Path)
	if err != nil {
		return fmt.Errorf("%w: read policy: %v", ErrStale, err)
	}
	sum := sha256.Sum256(data)
	if fmt.Sprintf("%x", sum) != policy.Hash {
		return fmt.Errorf("%w: policy changed", ErrStale)
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
	return validateExistingDir(dir)
}

func validateExistingDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: state directory must be absolute", ErrInvalid)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
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
	if snapshot.Format == 1 {
		return fmt.Errorf("%w: snapshot format 1 is no longer supported; rerun vuelta scan", ErrInvalid)
	}
	if snapshot.Format != FormatVersion || !idPattern.MatchString(snapshot.ID) || snapshot.CreatedAt.IsZero() || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.CreatedAt) {
		return fmt.Errorf("%w: malformed snapshot metadata", ErrInvalid)
	}
	if snapshot.Policy.Path == "" || snapshot.Policy.Hash == "" || snapshot.Gates.MinReleaseAge == "" || !hashPattern.MatchString(snapshot.PolicyHash) {
		return fmt.Errorf("%w: incomplete policy identity", ErrInvalid)
	}
	minimumAge, err := time.ParseDuration(snapshot.Gates.MinReleaseAge)
	if err != nil || minimumAge < 0 {
		return fmt.Errorf("%w: malformed minimum release age", ErrInvalid)
	}
	if snapshot.Policy.Path != PolicyNone && !filepath.IsAbs(snapshot.Policy.Path) {
		return fmt.Errorf("%w: policy path must be canonical and absolute", ErrInvalid)
	}
	if snapshot.Policy.Path != PolicyNone && !hashPattern.MatchString(snapshot.Policy.Hash) {
		return fmt.Errorf("%w: malformed policy hash", ErrInvalid)
	}
	var hashes map[string]string
	switch snapshot.Origin {
	case OriginWorkspace:
		if snapshot.Project == "" || snapshot.AdhocPath != "" || !filepath.IsAbs(snapshot.Workspace.CanonicalPath) || snapshot.Workspace.BaseRevision == "" || !hashPattern.MatchString(snapshot.ConfigHash) || len(snapshot.Workspace.InputHashes) == 0 {
			return fmt.Errorf("%w: incomplete workspace identity", ErrInvalid)
		}
		hashes = snapshot.Workspace.InputHashes
	case OriginAdhoc:
		if snapshot.Project != "" || !filepath.IsAbs(snapshot.AdhocPath) || len(snapshot.InputHashes) == 0 {
			return fmt.Errorf("%w: incomplete adhoc identity", ErrInvalid)
		}
		hashes = snapshot.InputHashes
	default:
		return fmt.Errorf("%w: invalid snapshot origin", ErrInvalid)
	}
	for path, sum := range hashes {
		if path == "" || path == "." || filepath.IsAbs(path) || !hashPattern.MatchString(sum) {
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
