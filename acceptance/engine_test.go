//go:build realengine

package acceptance

import (
	"context"
	"encoding/json"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const caseTimeout = 12 * time.Minute

func checkEngine(t *testing.T, expected string) *config.DockerConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	isolatedConfig := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolatedConfig, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("[infrastructure] initialize isolated Docker config: %v", err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		command.Env = []string{"DOCKER_CONFIG=" + isolatedConfig}
		out, err := command.Output()
		if err != nil {
			t.Fatalf("[infrastructure] explicit Docker endpoint is unavailable: %v", err)
		}
		return out
	}
	versionOutput := run("version", "--format", `{"server_version":{{json .Server.Version}},"api_version":{{json .Server.APIVersion}},"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}}}`)
	infoOutput := run("info", "--format", `{"id":{{json .ID}},"security_options":{{json .SecurityOptions}},"name":{{json .Name}}}`)
	var version dockerVersionIdentity
	if err := json.Unmarshal(versionOutput, &version); err != nil {
		t.Fatalf("[infrastructure] decode Docker version identity: %v", err)
	}
	var info struct {
		dockerInfoIdentity
		Name string `json:"name"`
	}
	if err := json.Unmarshal(infoOutput, &info); err != nil {
		t.Fatalf("[infrastructure] decode Docker capability identity: %v", err)
	}
	if info.ID == "" || version.ServerVersion == "" || version.APIVersion == "" || len(info.SecurityOptions) == 0 {
		t.Fatal("[infrastructure] Docker daemon omitted required identity fields")
	}
	architecture, err := dockerexec.NormalizeArchitecture(version.Architecture)
	if err != nil {
		t.Fatalf("[compatibility] Docker architecture: %v", err)
	}
	text := strings.ToLower(info.Name)
	operatingSystem := strings.ToLower(version.OperatingSystem)
	isDesktop := strings.Contains(text, "docker desktop") || strings.Contains(text, "docker-desktop") || strings.Contains(operatingSystem, "docker desktop")
	if expected != "" && (expected == "docker-desktop") != isDesktop {
		t.Fatalf("[infrastructure] matrix expects %s but endpoint reports a different engine", expected)
	}
	return &config.DockerConfig{Developer: &config.DockerEndpointConfig{
		Socket: "/var/run/docker.sock",
		ExpectedDaemon: config.DockerDaemonIdentity{
			ID: info.ID, ServerVersion: version.ServerVersion, OperatingSystem: version.OperatingSystem,
			Architecture: architecture, MinimumAPIVersion: version.APIVersion,
			RequiredSecurityOptions: append([]string(nil), info.SecurityOptions...),
		},
	}}
}

func commitFixtureFiles(t *testing.T, ctx context.Context, project, message string, files ...string) {
	t.Helper()
	commands := [][]string{{"add"}}
	commands[0] = append(commands[0], files...)
	commands = append(commands, []string{"commit", "-q", "-m", message})
	for _, args := range commands {
		command := exec.CommandContext(ctx, "git", args...)
		command.Dir = project
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("[infrastructure] commit Vuelta onboarding: %v: %s", err, output)
		}
	}
}

func runGitOutput(t *testing.T, ctx context.Context, dir string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = dir
	output, err := command.Output()
	if err != nil {
		t.Fatalf("[infrastructure] git %v: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}

type dockerVersionIdentity struct {
	ServerVersion   string `json:"server_version"`
	APIVersion      string `json:"api_version"`
	OperatingSystem string `json:"os"`
	Architecture    string `json:"architecture"`
}
type dockerInfoIdentity struct {
	ID              string   `json:"id"`
	SecurityOptions []string `json:"security_options"`
}

func runTextInDir(t *testing.T, ctx context.Context, env []string, dir, category, binary string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = env
	command.Dir = dir
	data, err := command.Output()
	if err != nil {
		t.Fatalf("[%s] command failed: %v", category, err)
	}
	return string(data)
}

// Give every real acceptance invocation its own egress namespace so tests in
// different runner containers cannot share live network attachments.
func isolatedRepairEgress(t *testing.T, cfg *config.Config) {
	t.Helper()
	id, err := runlease.NewID()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Update.Egress.Network = "vuelta-acceptance-" + id[:12]
	cfg.Update.Egress.ProxyContainer = "vuelta-acceptance-proxy-" + id[:12]
	cfg.Update.Egress.ProxyURL = "http://" + cfg.Update.Egress.ProxyContainer + ":3128"
}
