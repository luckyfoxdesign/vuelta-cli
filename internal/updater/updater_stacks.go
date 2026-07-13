package updater

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var ncuVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func validateNCUVersion(version string) error {
	if !ncuVersionPattern.MatchString(version) {
		return fmt.Errorf("must be an exact semantic version (MAJOR.MINOR.PATCH), got %q", version)
	}
	return nil
}

// lockDigest hashes a lock file's contents so callers can detect whether a
// package-manager invocation actually changed anything. A missing lock
// file hashes to a distinct sentinel so "file appeared" also counts as a
// change.
func lockDigest(projectPath, lockFile string) (string, error) {
	data, err := os.ReadFile(filepath.Join(projectPath, lockFile))
	if os.IsNotExist(err) {
		return "<missing>", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", lockFile, err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// PoetryUpdater runs `poetry update` for a python/poetry workspace.
type PoetryUpdater struct {
	Image string
	Run   DockerRunner
}

func (u PoetryUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	before, err := lockDigest(projectPath, "poetry.lock")
	if err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"poetry", "update"}, projectPath); err != nil {
		return false, err
	}
	after, err := lockDigest(projectPath, "poetry.lock")
	if err != nil {
		return false, err
	}
	return before != after, nil
}

// UVUpdater runs `uv lock --upgrade` for a python/uv workspace.
type UVUpdater struct {
	Image string
	Run   DockerRunner
}

func (u UVUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	before, err := lockDigest(projectPath, "uv.lock")
	if err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"uv", "lock", "--upgrade"}, projectPath); err != nil {
		return false, err
	}
	after, err := lockDigest(projectPath, "uv.lock")
	if err != nil {
		return false, err
	}
	return before != after, nil
}

// PipToolsUpdater runs `pip-compile --upgrade requirements.in` for a
// python/pip-tools workspace.
type PipToolsUpdater struct {
	Image string
	Run   DockerRunner
}

func (u PipToolsUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	before, err := lockDigest(projectPath, "requirements.txt")
	if err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"pip-compile", "--upgrade", "requirements.in"}, projectPath); err != nil {
		return false, err
	}
	after, err := lockDigest(projectPath, "requirements.txt")
	if err != nil {
		return false, err
	}
	return before != after, nil
}

// NPMUpdater runs a pinned npm-check-updates version followed by
// `npm install` for a node/npm workspace, per part A §6.
type NPMUpdater struct {
	Image      string
	NCUVersion string
	Run        DockerRunner
}

func (u NPMUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	if err := validateNCUVersion(u.NCUVersion); err != nil {
		return false, fmt.Errorf("validate npm-check-updates version: %w", err)
	}
	before, err := lockDigest(projectPath, "package-lock.json")
	if err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"npx", "npm-check-updates@" + u.NCUVersion, "-u"}, projectPath); err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"npm", "install"}, projectPath); err != nil {
		return false, err
	}
	after, err := lockDigest(projectPath, "package-lock.json")
	if err != nil {
		return false, err
	}
	return before != after, nil
}

// BunUpdater runs a pinned npm-check-updates version followed by `bun install`
// for a node/bun workspace. The commands are separate argv lists so neither
// the configured version nor package metadata is interpreted by a shell.
type BunUpdater struct {
	Image      string
	NCUVersion string
	Run        DockerRunner
}

func (u BunUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	if err := validateNCUVersion(u.NCUVersion); err != nil {
		return false, fmt.Errorf("validate npm-check-updates version: %w", err)
	}
	before, err := lockDigest(projectPath, "bun.lock")
	if err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"bunx", "npm-check-updates@" + u.NCUVersion, "-u"}, projectPath); err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"bun", "install"}, projectPath); err != nil {
		return false, err
	}
	after, err := lockDigest(projectPath, "bun.lock")
	if err != nil {
		return false, err
	}
	return before != after, nil
}

// PNPMUpdater runs `pnpm up --latest` for a node/pnpm workspace.
type PNPMUpdater struct {
	Image string
	Run   DockerRunner
}

func (u PNPMUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	before, err := lockDigest(projectPath, "pnpm-lock.yaml")
	if err != nil {
		return false, err
	}
	if _, err := u.Run(ctx, u.Image, []string{"pnpm", "up", "--latest"}, projectPath); err != nil {
		return false, err
	}
	after, err := lockDigest(projectPath, "pnpm-lock.yaml")
	if err != nil {
		return false, err
	}
	return before != after, nil
}
