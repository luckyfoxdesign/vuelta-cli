package gitexec

import (
	"context"
	"crypto/sha1" // #nosec G505 -- Git SHA-1 object identity, not a security digest.
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/gitpath"
)

// WorktreeChange is a raw, no-filter comparison against one immutable commit.
// Status is A, M, or D. Mode is the current regular-file Git mode for A/M.
type WorktreeChange struct {
	Status string
	Path   string
	Mode   string
}

type treeEntry struct {
	mode   string
	object string
	path   string
}

// InspectWorktree compares the index and filesystem to base without invoking
// status, checkout, clean/smudge filters, textconv, or external diff. Files are
// hashed as literal Git blobs in Go. A repository that relies on executable
// content filters therefore fails closed as dirty instead of running them.
func InspectWorktree(ctx context.Context, dir, base string) ([]WorktreeChange, error) {
	if err := ValidateCommitSHA(base); err != nil {
		return nil, err
	}
	formatOut, err := Output(ctx, dir, "rev-parse", "--show-object-format")
	if err != nil {
		return nil, err
	}
	objectFormat := strings.TrimSpace(string(formatOut))
	if objectFormat != "sha1" && objectFormat != "sha256" {
		return nil, errors.New("unsupported Git object format")
	}
	treeOut, err := Output(ctx, dir, "ls-tree", "-r", "-z", "--full-tree", base)
	if err != nil {
		return nil, err
	}
	entries, err := parseTreeEntries(treeOut)
	if err != nil {
		return nil, err
	}
	changes := make(map[string]WorktreeChange)
	for _, entry := range entries {
		if entry.mode != "100644" && entry.mode != "100755" && entry.mode != "120000" {
			return nil, fmt.Errorf("tracked path %q has unsupported Git mode %s", entry.path, entry.mode)
		}
		full := filepath.Join(dir, filepath.FromSlash(entry.path))
		info, statErr := os.Lstat(full)
		if os.IsNotExist(statErr) {
			changes[entry.path] = WorktreeChange{Status: "D", Path: entry.path}
			continue
		}
		if statErr != nil {
			return nil, fmt.Errorf("inspect tracked path %q: %w", entry.path, statErr)
		}
		mode, object, hashErr := literalBlob(full, info, objectFormat)
		if hashErr != nil {
			return nil, fmt.Errorf("hash tracked path %q: %w", entry.path, hashErr)
		}
		if mode != entry.mode || object != entry.object {
			changes[entry.path] = WorktreeChange{Status: "M", Path: entry.path, Mode: mode}
		}
	}

	otherOut, err := Output(ctx, dir, "ls-files", "--others", "--exclude-standard", "-z", "--")
	if err != nil {
		return nil, err
	}
	otherPaths, err := splitNULBytes(otherOut)
	if err != nil {
		return nil, fmt.Errorf("parse untracked Git paths: %w", err)
	}
	for _, rel := range otherPaths {
		if err := gitpath.ValidatePath(rel); err != nil {
			return nil, err
		}
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("untracked path %q is not a regular file", rel)
		}
		mode := "100644"
		if info.Mode().Perm()&0o111 != 0 {
			mode = "100755"
		}
		changes[rel] = WorktreeChange{Status: "A", Path: rel, Mode: mode}
	}

	indexOut, err := Output(ctx, dir, "diff-index", "--cached", "--name-status", "-z", "--no-renames", base, "--")
	if err != nil {
		return nil, err
	}
	indexFields, err := splitNULBytes(indexOut)
	if err != nil || len(indexFields)%2 != 0 {
		return nil, errors.New("parse staged Git name/status output")
	}
	for i := 0; i < len(indexFields); i += 2 {
		rel := indexFields[i+1]
		if err := gitpath.ValidatePath(rel); err != nil {
			return nil, err
		}
		if _, already := changes[rel]; !already {
			changes[rel] = WorktreeChange{Status: "M", Path: rel}
		}
	}

	result := make([]WorktreeChange, 0, len(changes))
	for _, entry := range entries {
		if change, ok := changes[entry.path]; ok {
			result = append(result, change)
			delete(changes, entry.path)
		}
	}
	for _, rel := range otherPaths {
		if change, ok := changes[rel]; ok {
			result = append(result, change)
			delete(changes, rel)
		}
	}
	for _, change := range changes {
		result = append(result, change)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func parseTreeEntries(out []byte) ([]treeEntry, error) {
	fields, err := splitNULBytes(out)
	if err != nil {
		return nil, fmt.Errorf("parse Git tree: %w", err)
	}
	entries := make([]treeEntry, 0, len(fields))
	for _, field := range fields {
		header, rel, ok := strings.Cut(field, "\t")
		parts := strings.Fields(header)
		if !ok || len(parts) != 3 || parts[1] != "blob" {
			return nil, errors.New("git tree contains a non-blob entry")
		}
		if err := gitpath.ValidatePath(rel); err != nil {
			return nil, err
		}
		entries = append(entries, treeEntry{mode: parts[0], object: parts[2], path: rel})
	}
	return entries, nil
}

func literalBlob(path string, info os.FileInfo, objectFormat string) (string, string, error) {
	var data io.Reader
	var size int64
	mode := "100644"
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return "", "", err
		}
		data = strings.NewReader(target)
		size = int64(len(target))
		mode = "120000"
	} else {
		if !info.Mode().IsRegular() {
			return "", "", errors.New("path is not a regular file or symlink")
		}
		file, err := os.Open(path)
		if err != nil {
			return "", "", err
		}
		defer func() { _ = file.Close() }()
		data = file
		size = info.Size()
		if info.Mode().Perm()&0o111 != 0 {
			mode = "100755"
		}
	}
	var digest hash.Hash
	if objectFormat == "sha256" {
		digest = sha256.New()
	} else {
		digest = sha1.New() // #nosec G401 -- Git SHA-1 object identity.
	}
	_, _ = fmt.Fprintf(digest, "blob %d%c", size, byte(0))
	if _, err := io.Copy(digest, data); err != nil {
		return "", "", err
	}
	return mode, fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func splitNULBytes(out []byte) ([]string, error) {
	if len(out) == 0 {
		return nil, nil
	}
	if out[len(out)-1] != 0 {
		return nil, errors.New("output is not NUL-terminated")
	}
	return strings.Split(string(out[:len(out)-1]), "\x00"), nil
}
