// Package egress resolves the checked-in, fail-closed Docker egress policy
// shared by containers that need approved registry access.
package egress

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

// ErrPolicyUnavailable means the required registry allowlist policy could not
// be verified. Callers must not fall back to Docker's default bridge network.
var ErrPolicyUnavailable = errors.New("egress policy unavailable")

// Resolve verifies the configured internal network and its running proxy, then
// returns the only Docker network and proxy URL a caller may use for egress.
func Resolve(ctx context.Context, cfg config.EgressConfig) (network, proxyURL string, err error) {
	return ResolveWith(ctx, cfg, dockerexec.Default())
}

// ResolveWith verifies the egress policy through the supplied Docker boundary.
func ResolveWith(ctx context.Context, cfg config.EgressConfig, docker dockerexec.Runner) (network, proxyURL string, err error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if err := dockerInspect(ctx, docker, "network", cfg.Network); err != nil {
		return "", "", fmt.Errorf("%w: network %q is unavailable; run `docker compose up -d egress-proxy`: %v", ErrPolicyUnavailable, cfg.Network, err)
	}
	if err := dockerContainerRunning(ctx, docker, cfg.ProxyContainer); err != nil {
		return "", "", fmt.Errorf("%w: proxy container %q is unavailable; run `docker compose up -d egress-proxy`: %v", ErrPolicyUnavailable, cfg.ProxyContainer, err)
	}
	if cfg.ProxyURL == "" {
		return "", "", ErrPolicyUnavailable
	}
	return cfg.Network, cfg.ProxyURL, nil
}

func dockerInspect(ctx context.Context, docker dockerexec.Runner, kind, name string) error {
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args: []string{kind, "inspect", name}, Combined: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return fmt.Errorf("docker %s inspect: %w", kind, err)
	}
	return nil
}

func dockerContainerRunning(ctx context.Context, docker dockerexec.Runner, name string) error {
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:     []string{"container", "inspect", "--format", "{{.State.Running}}", name},
		Combined: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return fmt.Errorf("docker container inspect: %w", err)
	}
	if strings.TrimSpace(string(result.Combined)) != "true" {
		return errors.New("container is not running")
	}
	return nil
}
