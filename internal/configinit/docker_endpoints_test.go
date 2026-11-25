package configinit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestBootstrapPreservesAndUpdatesTrustedEndpoints(t *testing.T) {
	first := config.DockerEndpointConfig{Socket: "/approved/first.sock", ExpectedDaemon: config.DockerDaemonIdentity{
		ID: "first", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
		MinimumAPIVersion: "1.44", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
	}}
	second := first
	second.Socket, second.ExpectedDaemon.ID = "/approved/second.sock", "second"
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "list", true: "legacy"}[legacy], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			cfg := NewConfig()
			cfg.Docker = &config.DockerConfig{DeveloperEndpoints: []config.DockerEndpointConfig{first}}
			if legacy {
				cfg.Docker = &config.DockerConfig{Developer: &first}
			}
			if err := Write(cfg, path, false); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), "socket: /approved/first.sock", "socket: /approved/first.sock # keep socket comment", 1))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded.Docker.TrustedDeveloperEndpoints(), []config.DockerEndpointConfig{first}) {
				t.Fatal("single endpoint did not load")
			}
			for _, endpoint := range []config.DockerEndpointConfig{second, first, second} {
				plan, err := PlanDockerBootstrap(path, endpoint)
				if err != nil {
					t.Fatal(err)
				}
				if err := plan.Apply(path); err != nil {
					t.Fatal(err)
				}
			}
			loaded, err = config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			updated, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(updated), "# keep socket comment") {
				t.Fatal("bootstrap erased an existing endpoint comment")
			}
			if loaded.Docker.Developer != nil || !reflect.DeepEqual(loaded.Docker.DeveloperEndpoints, []config.DockerEndpointConfig{first, second}) {
				t.Fatalf("trusted endpoints = %#v", loaded.Docker)
			}
			second.ExpectedDaemon.ID = "reviewed-replacement"
			plan, err := PlanDockerBootstrap(path, second)
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Apply(path); err != nil {
				t.Fatal(err)
			}
			loaded, err = config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded.Docker.DeveloperEndpoints, []config.DockerEndpointConfig{first, second}) {
				t.Fatalf("update changed order or erased trust: %#v", loaded.Docker)
			}
		})
	}
}

func TestBootstrapIgnoresNullEndpointFields(t *testing.T) {
	endpoint := config.DockerEndpointConfig{Socket: "/approved/docker.sock", ExpectedDaemon: config.DockerDaemonIdentity{
		ID: "daemon", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
		MinimumAPIVersion: "1.44", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
	}}
	for _, field := range []string{"developer", "developer_endpoints"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := Write(NewConfig(), path, false); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, []byte("docker:\n  "+field+": null\n")...)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanDockerBootstrap(path, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Parse(plan.Updated)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.Docker.TrustedDeveloperEndpoints(), []config.DockerEndpointConfig{endpoint}) {
				t.Fatalf("endpoints = %#v", cfg.Docker)
			}
		})
	}
}
