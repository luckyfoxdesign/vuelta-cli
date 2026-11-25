//go:build darwin && realengine

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

// TestDesktopOrbStackTrust uses an isolated --config and explicit local sockets.
// Cross-compile with Docker, then run the test binary on the Mac hosting both engines.
func TestDesktopOrbStackTrust(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	desktop := filepath.Join(home, ".docker", "run", "docker.sock")
	orbstack := filepath.Join(home, ".orbstack", "run", "docker.sock")
	path := filepath.Join(t.TempDir(), "config.yaml")
	bootstrap := func(path, socket string) {
		t.Helper()
		if err := run([]string{"--no-input", "--config", path, "environment", "bootstrap", "--socket", socket, "--yes"}); err != nil {
			t.Fatal(err)
		}
	}
	load := func(path string) config.Config {
		t.Helper()
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		return *cfg
	}
	verify := func(cfg config.Config) (*dockerexec.Executor, error) {
		t.Helper()
		if err := configureDeveloperDocker(cfg); err != nil {
			return nil, err
		}
		executor := dockerexec.Default().(*dockerexec.Executor)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		_, err := executor.Run(ctx, dockerexec.Request{Args: []string{"version"}})
		return executor, err
	}
	assertSocket := func(cfg config.Config, want string) {
		t.Helper()
		executor, err := verify(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if socket, err := executor.SocketPath(); err != nil || socket != want {
			t.Fatalf("selected = %s, %v; want %s", socket, err, want)
		}
	}

	bootstrap(path, desktop)
	bootstrap(path, orbstack)
	cfg := load(path)
	endpoints := cfg.Docker.DeveloperEndpoints
	if len(endpoints) != 2 || endpoints[0].Socket != desktop || endpoints[1].Socket != orbstack {
		t.Fatalf("bootstrap did not preserve endpoint order: %#v", cfg.Docker)
	}
	if endpoints[0].ExpectedDaemon.ID == endpoints[1].ExpectedDaemon.ID {
		t.Fatal("acceptance requires two distinct Docker daemons")
	}
	assertSocket(cfg, desktop)
	cfg.Docker.DeveloperEndpoints = []config.DockerEndpointConfig{endpoints[1], endpoints[0]}
	assertSocket(cfg, orbstack)
	cfg.Docker.DeveloperEndpoints = []config.DockerEndpointConfig{endpoints[0], endpoints[1]}
	cfg.Docker.DeveloperEndpoints[0].ExpectedDaemon.ID = "acceptance-identity-mismatch"
	_, err = verify(cfg)
	var attestation *dockerexec.AttestationError
	if !errors.As(err, &attestation) {
		t.Fatalf("identity mismatch accepted or hidden by fallback: %v", err)
	}

	// Bootstrap two explicit aliases while live, then remove them to model
	// unavailable approved sockets without stopping either user's engine.
	fallbackPath := filepath.Join(t.TempDir(), "config.yaml")
	firstAlias := filepath.Join(t.TempDir(), "desktop.sock")
	secondAlias := filepath.Join(t.TempDir(), "orbstack.sock")
	if err := os.Symlink(desktop, firstAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(orbstack, secondAlias); err != nil {
		t.Fatal(err)
	}
	bootstrap(fallbackPath, firstAlias)
	bootstrap(fallbackPath, secondAlias)
	if err := os.Remove(firstAlias); err != nil {
		t.Fatal(err)
	}
	assertSocket(load(fallbackPath), secondAlias)
	if err := os.Remove(secondAlias); err != nil {
		t.Fatal(err)
	}
	_, err = verify(load(fallbackPath))
	if err == nil || !strings.Contains(err.Error(), "no trusted Docker endpoint is available") {
		t.Fatalf("unavailable error = %v", err)
	}
}
