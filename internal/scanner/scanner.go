// Package scanner validates the explicitly configured project paths and
// determines each project's stack. It never walks parent directories or
// discovers projects on its own; only workspaces[] from the config are
// ever considered.
package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
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
	CanonicalPath     string
	Remote            string
	BaseRevision      string
	InputStages       []string
	InputManifestHash string
	InputHashes       map[string]string
	InputCategories   []string
}

// IdentityOptions records the exact stage contracts used by a scan.
type IdentityOptions struct {
	Stages             []scaninput.Stage
	AllowProjectConfig bool
	PolicyFile         string
}

// RequiredTools lists host binaries the pipeline needs before it can run
// any workspace.
var RequiredTools = []string{"git", "docker"}

// CheckTools verifies every required host tool is on PATH.
func CheckTools() error {
	return CheckToolsWithDocker(dockerexec.Default())
}

// CheckToolsWithDocker verifies host tools while binding Docker checks to the
// same approved executable that later commands will use.
func CheckToolsWithDocker(docker dockerexec.Runner) error {
	return checkToolsWithDocker(RequiredTools, docker)
}

func checkTools(tools []string) error {
	return checkToolsWithDocker(tools, dockerexec.Default())
}

func checkToolsWithDocker(tools []string, docker dockerexec.Runner) error {
	var missing []string
	for _, tool := range tools {
		var err error
		switch tool {
		case "docker":
			_, err = docker.Path()
		case "git":
			_, err = gitexec.Default().Path()
		default:
			_, err = exec.LookPath(tool)
		}
		if err != nil {
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
		if err := gitexec.ValidateRemoteName(ws.Remote); err != nil {
			return PreflightResult{}, err
		}
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
	stages := make([]scaninput.Stage, 0, 2)
	if ws.PackageManager != "" {
		stages = append(stages, scaninput.StagePackageCandidates)
	}
	if ws.DockerImages != nil {
		stages = append(stages, scaninput.StageDockerManifest)
	}
	return IdentityForSnapshotWithOptions(ctx, ws, IdentityOptions{Stages: stages})
}

// IdentityForSnapshotWithOptions repeats preflight and binds the exact typed
// input manifest used by package/vulnerability scan stages.
func IdentityForSnapshotWithOptions(ctx context.Context, ws config.Workspace, options IdentityOptions) (SnapshotIdentity, error) {
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
	contracts, stages, err := InputContracts(ws, options)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	manifests := make([]scaninput.Manifest, 0, len(contracts))
	for _, contract := range contracts {
		bundle, buildErr := scaninput.Build(ctx, pre.CanonicalPath, pre.CanonicalPath, scaninput.Options{RequireTracked: true}, contract)
		if buildErr != nil {
			return SnapshotIdentity{}, buildErr
		}
		manifests = append(manifests, bundle.Manifest)
		bundle.Destroy()
	}
	manifest, err := scaninput.Combine(manifests...)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	stageNames := make([]string, 0, len(stages))
	for _, stage := range stages {
		stageNames = append(stageNames, string(stage))
	}
	return SnapshotIdentity{
		CanonicalPath: pre.CanonicalPath, Remote: strings.TrimSpace(remoteURL), BaseRevision: strings.TrimSpace(revision),
		InputStages: stageNames, InputManifestHash: manifest.Hash, InputHashes: manifest.InputHashes,
		InputCategories: scaninput.ManifestCategories(manifest),
	}, nil
}

// InputContracts returns deterministic contracts for snapshot creation,
// revalidation, and path-free diagnostics.
func InputContracts(ws config.Workspace, options IdentityOptions) ([]scaninput.Contract, []scaninput.Stage, error) {
	values := make([]string, 0, len(options.Stages))
	for _, stage := range options.Stages {
		values = append(values, string(stage))
	}
	stages, err := scaninput.ParseStages(values)
	if err != nil {
		return nil, nil, err
	}
	contracts := make([]scaninput.Contract, 0, len(stages))
	for _, stage := range stages {
		switch stage {
		case scaninput.StagePackageCandidates:
			contract, contractErr := scaninput.PackageContract(ws, options.AllowProjectConfig)
			if contractErr != nil {
				return nil, nil, contractErr
			}
			contracts = append(contracts, contract)
		case scaninput.StageDependencyCVE:
			contract, contractErr := scaninput.DependencyContract(ws)
			if contractErr != nil {
				return nil, nil, contractErr
			}
			contracts = append(contracts, contract)
		case scaninput.StageDockerManifest:
			contracts = append(contracts, scaninput.DockerContract(ws))
		case scaninput.StagePolicy:
			if options.PolicyFile == "" {
				return nil, nil, fmt.Errorf("vulnerability policy stage has no configured policy")
			}
			contracts = append(contracts, scaninput.PolicyContract(options.PolicyFile))
		}
	}
	return contracts, stages, nil
}

func isClean(ctx context.Context, path string) (bool, error) {
	out, err := runGit(ctx, path, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return false, err
	}
	head := strings.TrimSpace(out)
	changes, err := gitexec.InspectWorktree(ctx, path, head)
	if err != nil {
		return false, err
	}
	return len(changes) == 0, nil
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
	out, err := gitexec.Output(ctx, dir, args...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("git %s: %w", args[0], err)
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
