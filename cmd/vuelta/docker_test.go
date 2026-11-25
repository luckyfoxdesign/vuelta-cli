package main

import (
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestCleanupEndpointIsPinnedToParentSocket(t *testing.T) {
	first := config.DockerEndpointConfig{Socket: "/first.sock", ExpectedDaemon: config.DockerDaemonIdentity{ID: "first"}}
	second := config.DockerEndpointConfig{Socket: "/second.sock", ExpectedDaemon: config.DockerDaemonIdentity{ID: "second"}}
	cfg := config.Config{Docker: &config.DockerConfig{DeveloperEndpoints: []config.DockerEndpointConfig{first, second}}}
	endpoint, err := configuredCleanupEndpoint(cfg, second.Socket)
	if err != nil || endpoint.SocketPath != second.Socket || endpoint.Expected.ID != "second" {
		t.Fatalf("cleanup endpoint = %#v, %v", endpoint, err)
	}
	if _, err := configuredCleanupEndpoint(cfg, "/unknown.sock"); err == nil {
		t.Fatal("accepted untrusted cleanup socket")
	}
	cfg.Docker = &config.DockerConfig{Developer: &first}
	if _, err := configuredCleanupEndpoint(cfg, first.Socket); err != nil {
		t.Fatal(err)
	}
}
