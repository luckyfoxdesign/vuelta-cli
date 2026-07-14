// Package egress resolves the checked-in, fail-closed Docker egress policy
// shared by containers that need approved registry access.
package egress

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

// ErrPolicyUnavailable means the required registry allowlist policy could not
// be verified. Callers must not fall back to Docker's default bridge network.
var ErrPolicyUnavailable = errors.New("egress policy unavailable")

// Resolve verifies the configured internal network and its running proxy, then
// returns the only Docker network and proxy URL a caller may use for egress.
func Resolve(ctx context.Context, cfg config.EgressConfig) (network, proxyURL string, err error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if err := dockerInspect(ctx, "network", cfg.Network); err != nil {
		return "", "", fmt.Errorf("%w: network %q is unavailable; run `docker compose up -d egress-proxy`: %v", ErrPolicyUnavailable, cfg.Network, err)
	}
	if err := dockerContainerRunning(ctx, cfg.ProxyContainer); err != nil {
		return "", "", fmt.Errorf("%w: proxy container %q is unavailable; run `docker compose up -d egress-proxy`: %v", ErrPolicyUnavailable, cfg.ProxyContainer, err)
	}
	if cfg.ProxyURL == "" {
		return "", "", ErrPolicyUnavailable
	}
	return cfg.Network, cfg.ProxyURL, nil
}

func dockerInspect(ctx context.Context, kind, name string) error {
	cmd := exec.CommandContext(ctx, "docker", kind, "inspect", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker %s inspect: %w: %s", kind, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dockerContainerRunning(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "docker", "container", "inspect", "--format", "{{.State.Running}}", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container inspect: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) != "true" {
		return errors.New("container is not running")
	}
	return nil
}
