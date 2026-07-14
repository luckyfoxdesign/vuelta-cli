// Package updater bumps dependency versions per stack (python/node/docker)
// inside a sandboxed working copy. Each stack implements the Updater
// interface; see part B of the spec for pipeline wiring.
package updater

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
)

// Updater updates dependency versions for a single project.
type Updater interface {
	Update(ctx context.Context, projectPath string) (changed bool, err error)
}

// DockerRunner executes a command inside image against workDir and returns
// its combined output. Tests inject a fake to avoid needing a real Docker
// daemon.
type DockerRunner func(ctx context.Context, image string, args []string, workDir string) (output string, err error)

// ErrEgressPolicyUnavailable is returned when the registry allowlist policy
// required for an update container has not been configured. The runner must
// not substitute Docker's unrestricted default bridge network.
var ErrEgressPolicyUnavailable = egress.ErrPolicyUnavailable

// NewDockerRunner returns a runner bound to the strict local egress policy.
// It never falls back to Docker's default bridge network.
func NewDockerRunner(egressConfig config.EgressConfig) DockerRunner {
	return func(ctx context.Context, image string, args []string, workDir string) (string, error) {
		network, proxyURL, err := egress.Resolve(ctx, egressConfig)
		if err != nil {
			return "", err
		}
		return runDocker(ctx, image, args, workDir, network, proxyURL)
	}
}

// RunDocker is the default update runner. Until a registry-scoped egress
// policy is supplied by the sandbox layer, it fails closed before Docker is
// started.
func RunDocker(ctx context.Context, image string, args []string, workDir string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", ErrEgressPolicyUnavailable
}

// runDocker starts a hardened update container using the network supplied by
// policy. It is kept separate from the policy adapter so every updater shares
// the same container baseline.
func runDocker(ctx context.Context, image string, args []string, workDir, network, proxyURL string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	dockerArgs := dockerRunArgs(image, args, workDir, network, proxyURL)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return string(out), ctxErr
		}
		return string(out), fmt.Errorf("docker run %s %s: %w: %s", image, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// dockerRunArgs builds the fixed security baseline for update containers.
// workDir is the one-off sandbox prepared by the caller, never the original
// Git worktree. No Docker socket, host namespace, or host environment is
// passed to the container.
func dockerRunArgs(image string, args []string, workDir, network, proxyURL string) []string {
	dockerArgs := append([]string{
		"run", "--rm",
		"--user", "65532:65532",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "1",
		"--memory", "1g",
		"--pids-limit", "256",
		"--network", network,
		"--env", "HTTP_PROXY=" + proxyURL,
		"--env", "HTTPS_PROXY=" + proxyURL,
		"--env", "http_proxy=" + proxyURL,
		"--env", "https_proxy=" + proxyURL,
		"--env", "NO_PROXY=localhost,127.0.0.1",
		"--env", "HOME=/tmp",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"-v", fmt.Sprintf("%s:/project", workDir),
		"-w", "/project",
		image,
	}, args...)
	return dockerArgs
}

// NoopUpdater reports no change; used for workspaces with nothing to update
// (e.g. stack=docker with no docker_images configured yet).
type NoopUpdater struct{}

func (NoopUpdater) Update(context.Context, string) (bool, error) { return false, nil }

// CompositeUpdater runs each Updater in order and reports changed if any of
// them changed something. Used to combine a stack's package-manager updater
// with a docker_images updater on the same workspace (part A §6).
type CompositeUpdater []Updater

func (c CompositeUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	changed := false
	for _, u := range c {
		didChange, err := u.Update(ctx, projectPath)
		if err != nil {
			return changed, err
		}
		changed = changed || didChange
	}
	return changed, nil
}

// Resolve picks the Updater(s) for a workspace based on its
// stack/package_manager and, if set, docker_images. config.Validate is
// assumed to have already rejected unknown stack/package_manager pairs and
// unpinned images; Resolve only fails on missing config.update entries that
// a chosen updater needs (e.g. no pinned image for the stack).
func Resolve(ws config.Workspace, cfg config.Config) (Updater, error) {
	var updaters []Updater
	runner := NewDockerRunner(cfg.Update.Egress)

	switch {
	case ws.Stack == config.StackPython && ws.PackageManager == "poetry":
		img, err := requireImage(cfg, "python-poetry")
		if err != nil {
			return nil, err
		}
		updaters = append(updaters, PoetryUpdater{Image: img, Run: runner})
	case ws.Stack == config.StackPython && ws.PackageManager == "uv":
		img, err := requireImage(cfg, "python-uv")
		if err != nil {
			return nil, err
		}
		updaters = append(updaters, UVUpdater{Image: img, Run: runner})
	case ws.Stack == config.StackPython && ws.PackageManager == "pip-tools":
		img, err := requireImage(cfg, "python-pip-tools")
		if err != nil {
			return nil, err
		}
		updaters = append(updaters, PipToolsUpdater{Image: img, Run: runner})
	case ws.Stack == config.StackNode && ws.PackageManager == "npm":
		img, err := requireImage(cfg, "node")
		if err != nil {
			return nil, err
		}
		ncuVersion, err := requireTool(cfg, "npm_check_updates")
		if err != nil {
			return nil, err
		}
		updaters = append(updaters, NPMUpdater{Image: img, NCUVersion: ncuVersion, Run: runner})
	case ws.Stack == config.StackNode && ws.PackageManager == "bun":
		img, err := requireImage(cfg, "bun")
		if err != nil {
			return nil, err
		}
		ncuVersion, err := requireTool(cfg, "npm_check_updates")
		if err != nil {
			return nil, err
		}
		updaters = append(updaters, BunUpdater{Image: img, NCUVersion: ncuVersion, Run: runner})
	case ws.Stack == config.StackNode && ws.PackageManager == "pnpm":
		img, err := requireImage(cfg, "node")
		if err != nil {
			return nil, err
		}
		updaters = append(updaters, PNPMUpdater{Image: img, Run: runner})
	case ws.Stack == config.StackDocker:
		// No package-manager updater; docker_images (below) is the only update source.
	default:
		return nil, fmt.Errorf("no updater for stack=%q package_manager=%q", ws.Stack, ws.PackageManager)
	}

	if ws.DockerImages != nil {
		updaters = append(updaters, DockerImageUpdater{Files: ws.DockerImages.Files, Resolve: ResolveDigestViaManifest})
	}

	switch len(updaters) {
	case 0:
		return NoopUpdater{}, nil
	case 1:
		return updaters[0], nil
	default:
		return CompositeUpdater(updaters), nil
	}
}

func requireImage(cfg config.Config, key string) (string, error) {
	img, ok := cfg.Update.Images[key]
	if !ok || img == "" {
		return "", fmt.Errorf("update.images[%s] is required", key)
	}
	return img, nil
}

func requireTool(cfg config.Config, key string) (string, error) {
	v, ok := cfg.Update.Tools[key]
	if !ok || v == "" {
		return "", fmt.Errorf("update.tools[%s] is required", key)
	}
	if key == "npm_check_updates" {
		if err := validateNCUVersion(v); err != nil {
			return "", fmt.Errorf("update.tools[%s]: %w", key, err)
		}
	}
	return v, nil
}
