// Package scanner validates the explicitly configured project paths and
// determines each project's stack. It never walks parent directories or
// discovers projects on its own; only workspaces[] from the config are
// ever considered.
package scanner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

// SkipReason explains why Preflight decided a workspace should be skipped
// for this run, rather than failed.
type SkipReason string

const (
	// SkipNone means the workspace passed preflight and the run may proceed.
	SkipNone SkipReason = ""
	// SkipDirty means the workspace has uncommitted or untracked changes.
	SkipDirty SkipReason = "workspace has uncommitted or untracked changes"
	// SkipRemote means the configured remote does not exist in the repo.
	SkipRemote SkipReason = "configured remote does not exist"
	// SkipStackFiles means on-disk manifest files do not match the
	// configured stack/package_manager.
	SkipStackFiles SkipReason = "workspace files do not match the configured stack/package_manager"
)

// PreflightResult is the outcome of validating one workspace before a
// pipeline run touches it.
type PreflightResult struct {
	CanonicalPath string
	Skip          SkipReason
}

// SnapshotIdentity is the immutable workspace metadata used to bind a package
// update plan to the exact project inputs that were scanned.
type SnapshotIdentity struct {
	CanonicalPath string
	Remote        string
	BaseRevision  string
	InputHashes   map[string]string
}

// RequiredTools lists host binaries the pipeline needs before it can run
// any workspace.
var RequiredTools = []string{"git", "docker"}

// CheckTools verifies every required host tool is on PATH.
func CheckTools() error {
	return checkTools(RequiredTools)
}

func checkTools(tools []string) error {
	var missing []string
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required tool(s) not found on PATH: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Preflight validates a single workspace: it resolves the canonical
// (symlink-free) path, checks the working tree is clean, that the
// configured remote exists, and that on-disk manifest files match the
// declared stack/package_manager. It only ever looks at ws.Path itself —
// no parent-directory scanning or project discovery.
func Preflight(ctx context.Context, ws config.Workspace) (PreflightResult, error) {
	canonical, err := filepath.EvalSymlinks(ws.Path)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("resolve canonical path %s: %w", ws.Path, err)
	}

	result := PreflightResult{CanonicalPath: canonical}

	clean, err := isClean(ctx, canonical)
	if err != nil {
		return PreflightResult{}, err
	}
	if !clean {
		result.Skip = SkipDirty
		return result, nil
	}

	if ws.Remote != "" {
		ok, err := hasRemote(ctx, canonical, ws.Remote)
		if err != nil {
			return PreflightResult{}, err
		}
		if !ok {
			result.Skip = SkipRemote
			return result, nil
		}
	}

	if !stackFilesPresent(canonical, ws) {
		result.Skip = SkipStackFiles
		return result, nil
	}

	return result, nil
}

// IdentityForSnapshot repeats the non-mutating preflight checks and returns
// the Git revision, configured remote URL, and hashes of the only files that
// package scanning is allowed to read. It never walks parent directories.
func IdentityForSnapshot(ctx context.Context, ws config.Workspace) (SnapshotIdentity, error) {
	pre, err := Preflight(ctx, ws)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	if pre.Skip != SkipNone {
		return SnapshotIdentity{}, fmt.Errorf("workspace cannot be snapshotted: %s", pre.Skip)
	}
	revision, err := runGit(ctx, pre.CanonicalPath, "rev-parse", "HEAD")
	if err != nil {
		return SnapshotIdentity{}, fmt.Errorf("resolve base revision: %w", err)
	}
	remoteURL := ""
	if ws.Remote != "" {
		remoteURL, err = runGit(ctx, pre.CanonicalPath, "remote", "get-url", ws.Remote)
		if err != nil {
			return SnapshotIdentity{}, fmt.Errorf("resolve remote URL: %w", err)
		}
	}
	hashes, err := inputHashes(pre.CanonicalPath, ws)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	return SnapshotIdentity{CanonicalPath: pre.CanonicalPath, Remote: strings.TrimSpace(remoteURL), BaseRevision: strings.TrimSpace(revision), InputHashes: hashes}, nil
}

func isClean(ctx context.Context, path string) (bool, error) {
	out, err := runGit(ctx, path, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "", nil
}

func hasRemote(ctx context.Context, path, remote string) (bool, error) {
	out, err := runGit(ctx, path, "remote")
	if err != nil {
		return false, err
	}
	for _, r := range strings.Fields(out) {
		if r == remote {
			return true, nil
		}
	}
	return false, nil
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// stackManifests maps each supported stack/package_manager pair to the
// manifest files that must be present at the workspace root. The docker
// stack has no manifest of its own here: it is validated via
// docker_images.files by config.Validate.
var stackManifests = map[string][]string{
	"python/poetry":    {"pyproject.toml", "poetry.lock"},
	"python/uv":        {"pyproject.toml", "uv.lock"},
	"python/pip-tools": {"requirements.in"},
	"node/npm":         {"package.json", "package-lock.json"},
	"node/pnpm":        {"package.json", "pnpm-lock.yaml"},
	"node/bun":         {"package.json", "bun.lock"},
}

func stackFilesPresent(path string, ws config.Workspace) bool {
	if ws.Stack == config.StackDocker {
		return true
	}
	key := ws.Stack + "/" + ws.PackageManager
	for _, f := range stackManifests[key] {
		if _, err := os.Stat(filepath.Join(path, f)); err != nil {
			return false
		}
	}
	return true
}

func inputHashes(root string, ws config.Workspace) (map[string]string, error) {
	files := append([]string(nil), stackManifests[ws.Stack+"/"+ws.PackageManager]...)
	if ws.DockerImages != nil {
		files = append(files, ws.DockerImages.Files...)
	}
	if len(files) == 0 {
		return nil, errors.New("workspace has no configured update input files")
	}
	hashes := make(map[string]string, len(files))
	for _, rel := range files {
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(filepath.Clean(rel), ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("invalid update input path %q", rel)
		}
		info, err := os.Lstat(filepath.Join(root, rel))
		if err != nil {
			return nil, fmt.Errorf("stat update input %s: %w", rel, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("update input %s is not a regular file", rel)
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, fmt.Errorf("read update input %s: %w", rel, err)
		}
		sum := sha256.Sum256(data)
		hashes[rel] = fmt.Sprintf("%x", sum)
	}
	return hashes, nil
}
