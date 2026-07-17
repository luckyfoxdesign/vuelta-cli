// Package updater bumps dependency versions per stack (python/node/docker)
// inside a sandboxed working copy. Each stack implements the Updater
// interface; see part B of the spec for pipeline wiring.
package updater

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/scancontainer"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

// Output bounds for untrusted container output (F5-MED-008). Discovery output
// is parsed as JSON, so it gets a hard cap: exceeding it kills the container
// client and fails the scan instead of parsing a truncated document. Apply
// output is diagnostics only, so it gets a soft bounded tail with a
// deterministic truncation marker.
const (
	discoveryOutputMaxBytes = 8 << 20
	applyOutputTailBytes    = 128 << 10
)

// Updater updates dependency versions for a single project.
type Updater interface {
	Update(ctx context.Context, projectPath string) (changed bool, err error)
}

// DockerRunner executes a command inside image against workDir and returns
// its combined output. Tests inject a fake to avoid needing a real Docker
// daemon.
type DockerRunner func(ctx context.Context, image string, args []string, workDir string) (output string, err error)

// ReadOnlyDockerRunner executes discovery against an in-memory minimal input
// archive rather than a host directory mount.
type ReadOnlyDockerRunner func(ctx context.Context, image string, args []string, bundle scaninput.Bundle) (output string, err error)

// ErrEgressPolicyUnavailable is returned when the registry allowlist policy
// required for an update container has not been configured. The runner must
// not substitute Docker's unrestricted default bridge network.
var ErrEgressPolicyUnavailable = egress.ErrPolicyUnavailable

// NewDockerRunner returns a runner bound to the strict local egress policy.
// It never falls back to Docker's default bridge network.
func NewDockerRunner(egressConfig config.EgressConfig) DockerRunner {
	return NewDockerRunnerWith(dockerexec.Default(), egressConfig)
}

// NewDockerRunnerWith returns an update runner using the supplied boundary.
func NewDockerRunnerWith(docker dockerexec.Runner, egressConfig config.EgressConfig) DockerRunner {
	return func(ctx context.Context, image string, args []string, workDir string) (string, error) {
		network, proxyURL, err := egress.ResolveWith(ctx, egressConfig, docker)
		if err != nil {
			return "", err
		}
		return runDocker(ctx, docker, image, args, workDir, network, proxyURL)
	}
}

// NewReadOnlyDockerRunner executes package discovery in the same fail-closed
// egress environment as updates, but transfers only an in-memory allowlisted
// context and makes the final container root filesystem read-only. Tools can
// use /tmp only for ephemeral caches.
func NewReadOnlyDockerRunner(egressConfig config.EgressConfig) ReadOnlyDockerRunner {
	return NewReadOnlyDockerRunnerWith(dockerexec.Default(), egressConfig)
}

// NewReadOnlyDockerRunnerWith returns a discovery runner using the supplied boundary.
func NewReadOnlyDockerRunnerWith(docker dockerexec.Runner, egressConfig config.EgressConfig) ReadOnlyDockerRunner {
	return func(ctx context.Context, image string, args []string, bundle scaninput.Bundle) (string, error) {
		network, proxyURL, err := egress.ResolveWith(ctx, egressConfig, docker)
		if err != nil {
			return "", err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		result, err := (scancontainer.Runner{Docker: docker}).Run(ctx, scancontainer.Request{
			Image: image, Args: args, Archive: bundle.Archive, Network: network, Proxy: proxyURL,
			Memory: "1g", Tmpfs: "64m", Combined: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: discoveryOutputMaxBytes},
		})
		var limitErr *dockerexec.OutputLimitError
		if errors.As(err, &limitErr) {
			return "", fmt.Errorf("docker read-only scan %s %s: output exceeded %d bytes", image, strings.Join(args, " "), discoveryOutputMaxBytes)
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return string(result.Combined), ctxErr
			}
			return string(result.Combined), fmt.Errorf("docker read-only scan %s %s: %w", image, strings.Join(args, " "), err)
		}
		return string(result.Combined), nil
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
func runDocker(ctx context.Context, docker dockerexec.Runner, image string, args []string, workDir, network, proxyURL string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	result, err := docker.Run(ctx, dockerexec.Request{
		Args:     dockerRunArgs(image, args, workDir, network, proxyURL),
		Combined: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: applyOutputTailBytes},
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return string(result.Combined), ctxErr
		}
		return string(result.Combined), fmt.Errorf("docker run %s %s: %w", image, strings.Join(args, " "), err)
	}
	return string(result.Combined), nil
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
	return ResolveWithDocker(ws, cfg, dockerexec.Default())
}

// ResolveWithDocker binds every updater command to the supplied Docker boundary.
func ResolveWithDocker(ws config.Workspace, cfg config.Config, docker dockerexec.Runner) (Updater, error) {
	var updaters []Updater
	runner := NewDockerRunnerWith(docker, cfg.Update.Egress)

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
		updaters = append(updaters, DockerImageUpdater{Files: ws.DockerImages.Files, Resolve: DigestResolverWithDocker(docker)})
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
