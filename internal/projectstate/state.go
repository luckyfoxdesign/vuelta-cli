// Package projectstate owns the private, project-local Vuelta state rooted at
// <target>/.vuelta. The versioned <target>/.vuelta.yaml policy is deliberately
// outside this package and must never be hidden by state-directory handling.
package projectstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	StateDirectoryName = ".vuelta"
	SnapshotsName      = "snapshots"
	ReportName         = "last-scan.md"
	MaxReportBytes     = 256 << 10
)

// Target is one exact canonical project root. Resolution never walks parents
// or consults configured workspaces.
type Target struct {
	Root string
}

// Resolve canonicalizes exactly path and requires it to be a directory.
func Resolve(path string) (Target, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Target{}, fmt.Errorf("make target path absolute: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Target{}, fmt.Errorf("resolve target directory %s: %w", path, err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return Target{}, fmt.Errorf("stat target directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return Target{}, fmt.Errorf("%s is not a directory", path)
	}
	return Target{Root: filepath.Clean(canonical)}, nil
}

// FromCanonical validates that root is already an absolute canonical target.
func FromCanonical(root string) (Target, error) {
	if !filepath.IsAbs(root) {
		return Target{}, errors.New("project target must be absolute")
	}
	target, err := Resolve(root)
	if err != nil {
		return Target{}, err
	}
	if target.Root != filepath.Clean(root) {
		return Target{}, errors.New("project target must be canonical")
	}
	return target, nil
}

func (t Target) StateDir() string     { return filepath.Join(t.Root, StateDirectoryName) }
func (t Target) SnapshotsDir() string { return filepath.Join(t.StateDir(), SnapshotsName) }
func (t Target) ReportPath() string   { return filepath.Join(t.StateDir(), ReportName) }

// EnsureState creates and validates only <target>/.vuelta.
func (t Target) EnsureState() error {
	if _, err := FromCanonical(t.Root); err != nil {
		return err
	}
	return ensurePrivateDirectory(t.StateDir(), "project state")
}

// EnsureSnapshots creates and validates the state and snapshot directories.
func (t Target) EnsureSnapshots() error {
	if err := t.EnsureState(); err != nil {
		return err
	}
	return ensurePrivateDirectory(t.SnapshotsDir(), "snapshot state")
}

// ValidateSnapshots validates existing private state without creating it.
func (t Target) ValidateSnapshots() error {
	if _, err := FromCanonical(t.Root); err != nil {
		return err
	}
	if err := validatePrivateDirectory(t.StateDir(), "project state"); err != nil {
		return err
	}
	return validatePrivateDirectory(t.SnapshotsDir(), "snapshot state")
}

// WriteReport atomically replaces the informational Markdown report.
func (t Target) WriteReport(data []byte) error {
	if len(data) > MaxReportBytes {
		return fmt.Errorf("scan report exceeds %d bytes", MaxReportBytes)
	}
	if err := t.EnsureState(); err != nil {
		return err
	}
	path := t.ReportPath()
	if info, err := os.Lstat(path); err == nil {
		if err := ValidatePrivateFile(info, "scan report"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect scan report: %w", err)
	}
	tmp, err := os.CreateTemp(t.StateDir(), ".last-scan-*")
	if err != nil {
		return fmt.Errorf("create temporary scan report: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict temporary scan report: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary scan report: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary scan report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary scan report: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish scan report: %w", err)
	}
	if err := syncDirectory(t.StateDir()); err != nil {
		return fmt.Errorf("sync project state directory: %w", err)
	}
	return nil
}

// ReadBoundedRegular reads a protected regular file without allowing the
// caller to allocate based on an untrusted file size.
func ReadBoundedRegular(path, label string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := ValidatePrivateFile(info, label); err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	data, err := readBoundedNoFollow(path, label, info, maxBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	return data, nil
}

// ValidatePrivateFile enforces the type, ownership, and mode contract shared
// by reports and snapshots.
func ValidatePrivateFile(info os.FileInfo, label string) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular file", label)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s permissions must be 0600", label)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("%s is not owned by the current user", label)
	}
	return nil
}

func ensurePrivateDirectory(path, label string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s directory: %w", label, err)
	}
	return validatePrivateDirectory(path, label)
}

func validatePrivateDirectory(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s directory: %w", label, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s directory is not a real directory", label)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s directory permissions must be 0700", label)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("%s directory is not owned by the current user", label)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
