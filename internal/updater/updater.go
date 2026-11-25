// Package updater provides hardened container runners and image resolution for repair.
package updater

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
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
	discoveryErrorBytes     = 16 << 10
	applyOutputTailBytes    = 128 << 10
	defaultDiscoveryMemory  = "1g"
)

// DockerRunner executes a command inside image against workDir and returns
// its combined output. Tests inject a fake to avoid needing a real Docker
// daemon.
type DockerRunner func(ctx context.Context, image string, args []string, workDir string) (output string, err error)

// ReadOnlyScanOutput keeps machine-readable stdout isolated from bounded
// stderr diagnostics.
type ReadOnlyScanOutput struct {
	Stdout string
	Stderr string
}

// ReadOnlyDockerRunner executes discovery against an in-memory minimal input
// archive rather than a host directory mount.
type ReadOnlyDockerRunner func(ctx context.Context, image string, args []string, bundle scaninput.Bundle, memory string) (ReadOnlyScanOutput, error)

// ErrEgressPolicyUnavailable is returned when the registry allowlist policy
// required for an update container has not been configured. The runner must
// not substitute Docker's unrestricted default bridge network.
var ErrEgressPolicyUnavailable = egress.ErrPolicyUnavailable

// NewDockerRunner returns a runner bound to the strict local egress policy.
// It never falls back to Docker's default bridge network.
func NewDockerRunner(egressConfig config.EgressConfig) DockerRunner {
	return NewDockerRunnerWithUser(dockerexec.Default(), egressConfig, "")
}

// NewDockerRunnerWith returns an update runner using the supplied boundary.
func NewDockerRunnerWith(docker dockerexec.Runner, egressConfig config.EgressConfig) DockerRunner {
	return NewDockerRunnerWithUser(docker, egressConfig, "")
}

// NewDockerRunnerForUser binds mutable sandbox updates to the non-root user
// declared by the selected toolchain profile.
func NewDockerRunnerForUser(egressConfig config.EgressConfig, user string) DockerRunner {
	return NewDockerRunnerWithProfile(dockerexec.Default(), egressConfig, user, "")
}

// NewDockerRunnerWithUser returns an update runner with an explicit profile
// user. An empty user retains the legacy compatibility user.
func NewDockerRunnerWithUser(docker dockerexec.Runner, egressConfig config.EgressConfig, user string) DockerRunner {
	return NewDockerRunnerWithProfile(docker, egressConfig, user, "")
}

// NewDockerRunnerForProfile binds mutable sandbox updates to both the non-root
// identity and target platform declared by the selected toolchain profile.
func NewDockerRunnerForProfile(egressConfig config.EgressConfig, user, platform string) DockerRunner {
	return NewDockerRunnerWithProfile(dockerexec.Default(), egressConfig, user, platform)
}

// NewDockerRunnerWithProfile returns an update runner with explicit profile
// execution constraints. Config validation owns the platform allowlist.
func NewDockerRunnerWithProfile(docker dockerexec.Runner, egressConfig config.EgressConfig, user, platform string) DockerRunner {
	return func(ctx context.Context, image string, args []string, workDir string) (string, error) {
		network, proxyURL, err := egress.ResolveWith(ctx, egressConfig, docker)
		if err != nil {
			return "", err
		}
		return runDockerWithProfile(ctx, docker, image, args, workDir, network, proxyURL, user, platform)
	}
}

// NewReadOnlyDockerRunner executes package discovery in the same fail-closed
// egress environment as updates, but transfers only an in-memory allowlisted
// context and makes the final container root filesystem read-only. Tools can
// use /tmp only for ephemeral caches.
func NewReadOnlyDockerRunner(egressConfig config.EgressConfig) ReadOnlyDockerRunner {
	return NewReadOnlyDockerRunnerWithUser(dockerexec.Default(), egressConfig, "")
}

// NewReadOnlyDockerRunnerWith returns a discovery runner using the supplied boundary.
func NewReadOnlyDockerRunnerWith(docker dockerexec.Runner, egressConfig config.EgressConfig) ReadOnlyDockerRunner {
	return NewReadOnlyDockerRunnerWithUser(docker, egressConfig, "")
}

// NewReadOnlyDockerRunnerForUser binds discovery to the non-root user declared
// by the selected, acceptance-tested toolchain profile.
func NewReadOnlyDockerRunnerForUser(egressConfig config.EgressConfig, user string) ReadOnlyDockerRunner {
	return NewReadOnlyDockerRunnerWithProfile(dockerexec.Default(), egressConfig, user, "")
}

// NewReadOnlyDockerRunnerWithUser returns a discovery runner with an explicit
// profile user. An empty user retains the legacy 65532 compatibility path.
func NewReadOnlyDockerRunnerWithUser(docker dockerexec.Runner, egressConfig config.EgressConfig, user string) ReadOnlyDockerRunner {
	return NewReadOnlyDockerRunnerWithProfile(docker, egressConfig, user, "")
}

// NewReadOnlyDockerRunnerForProfile binds discovery to the selected profile's
// non-root identity and target platform.
func NewReadOnlyDockerRunnerForProfile(egressConfig config.EgressConfig, user, platform string) ReadOnlyDockerRunner {
	return NewReadOnlyDockerRunnerWithProfile(dockerexec.Default(), egressConfig, user, platform)
}

// NewReadOnlyDockerRunnerWithProfile returns a discovery runner with explicit
// profile execution constraints.
func NewReadOnlyDockerRunnerWithProfile(docker dockerexec.Runner, egressConfig config.EgressConfig, user, platform string) ReadOnlyDockerRunner {
	return func(ctx context.Context, image string, args []string, bundle scaninput.Bundle, memory string) (ReadOnlyScanOutput, error) {
		network, proxyURL, err := egress.ResolveWith(ctx, egressConfig, docker)
		if err != nil {
			return ReadOnlyScanOutput{}, err
		}
		if err := ctx.Err(); err != nil {
			return ReadOnlyScanOutput{}, err
		}
		if memory == "" {
			memory = defaultDiscoveryMemory
		}
		result, err := (scancontainer.Runner{Docker: docker}).Run(ctx, scancontainer.Request{
			Image: image, Platform: platform, User: user, Args: args, Archive: bundle.Archive, Network: network, Proxy: proxyURL,
			Memory: memory, Tmpfs: "64m",
			Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: discoveryOutputMaxBytes},
			Stderr: dockerexec.Capture{Mode: dockerexec.Excerpt, Bytes: discoveryErrorBytes},
		})
		output := ReadOnlyScanOutput{Stdout: string(result.Stdout), Stderr: string(result.Stderr)}
		var limitErr *dockerexec.OutputLimitError
		if errors.As(err, &limitErr) && limitErr.Stream == "stdout" {
			return output, fmt.Errorf("docker read-only scan output exceeded %d bytes", discoveryOutputMaxBytes)
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return output, ctxErr
			}
			return output, fmt.Errorf("docker read-only scan failed: %w", err)
		}
		return output, nil
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
func runDockerWithProfile(ctx context.Context, docker dockerexec.Runner, image string, args []string, workDir, network, proxyURL, user, platform string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	result, err := docker.Run(ctx, dockerexec.Request{
		Args:     dockerRunArgsForProfile(image, args, workDir, network, proxyURL, user, platform),
		Combined: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: applyOutputTailBytes},
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return string(result.Combined), ctxErr
		}
		detail := safeerr.Excerpt(result.Combined, 1024)
		if detail != "" {
			return string(result.Combined), fmt.Errorf("docker run %s %s: %w: %s", image, strings.Join(args, " "), err, detail)
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
	return dockerRunArgsForUser(image, args, workDir, network, proxyURL, "")
}

func dockerRunArgsForUser(image string, args []string, workDir, network, proxyURL, user string) []string {
	return dockerRunArgsForProfile(image, args, workDir, network, proxyURL, user, "")
}

func dockerRunArgsForProfile(image string, args []string, workDir, network, proxyURL, user, platform string) []string {
	if user == "" {
		user = "65532:65532"
	}
	dockerArgs := []string{"run", "--rm"}
	if platform != "" {
		dockerArgs = append(dockerArgs, "--platform", platform)
	}
	dockerArgs = append(dockerArgs,
		"--user", user,
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "1",
		"--memory", "1g",
		"--pids-limit", "256",
		"--network", network,
		"--env", "HTTP_PROXY="+proxyURL,
		"--env", "HTTPS_PROXY="+proxyURL,
		"--env", "http_proxy="+proxyURL,
		"--env", "https_proxy="+proxyURL,
		"--env", "NO_PROXY=localhost,127.0.0.1",
		"--env", "HOME=/tmp",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"-v", fmt.Sprintf("%s:/project", workDir),
		"-w", "/project",
		image,
	)
	return append(dockerArgs, args...)
}
