package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

var probeDockerEndpoint = dockerexec.Probe

type environmentBootstrapResult struct {
	Status  string                      `json:"status"`
	Config  string                      `json:"config"`
	Socket  string                      `json:"socket"`
	Daemon  config.DockerDaemonIdentity `json:"daemon"`
	Changed bool                        `json:"changed"`
}

func runEnvironmentBootstrap(args []string) error {
	fs := flag.NewFlagSet("environment bootstrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", "", "explicit local Docker Unix socket")
	yes := fs.Bool("yes", false, "confirm the displayed endpoint")
	jsonOutput := fs.Bool("json", false, "write the versioned JSON envelope")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting for values or confirmation")
	if err := fs.Parse(args); err != nil {
		return environmentBootstrapFailure(*jsonOutput, "invalid_invocation", fail(exitConfig, "%v", err))
	}
	if len(fs.Args()) > 1 {
		return environmentBootstrapFailure(*jsonOutput, "invalid_invocation", fail(exitConfig, "usage: vuelta environment bootstrap --socket PATH [--yes] [--json] [config-path]"))
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return environmentBootstrapFailure(*jsonOutput, "invalid_invocation", err)
	}
	if *socket == "" {
		if *nonInteractive {
			return environmentBootstrapFailure(*jsonOutput, "socket_required", fail(exitConfig, "non-interactive bootstrap requires an explicit --socket PATH"))
		}
		selected, promptErr := promptChoice("--socket", dockerSocketSuggestions())
		if promptErr != nil {
			return environmentBootstrapFailure(*jsonOutput, "socket_required", fail(exitConfig, "%v", promptErr))
		}
		*socket = selected
	}
	if !filepath.IsAbs(*socket) || strings.ContainsRune(*socket, '\x00') {
		return environmentBootstrapFailure(*jsonOutput, "socket_invalid", fail(exitConfig, "--socket must be an absolute local Unix socket path"))
	}

	identity, err := probeDockerEndpoint(context.Background(), *socket)
	if err != nil {
		return environmentBootstrapFailure(*jsonOutput, "endpoint_probe_failed", fail(exitEnv, "Docker endpoint probe failed: %v", err))
	}
	daemon := config.DockerDaemonIdentity{
		ID: identity.ID, ServerVersion: identity.ServerVersion,
		OperatingSystem: identity.OperatingSystem, Architecture: identity.Architecture,
		MinimumAPIVersion:       identity.MinimumAPIVersion,
		RequiredSecurityOptions: append([]string(nil), identity.RequiredSecurityOptions...),
	}
	sort.Strings(daemon.RequiredSecurityOptions)
	endpoint := config.DockerEndpointConfig{Socket: *socket, ExpectedDaemon: daemon}
	plan, err := configinit.PlanDockerBootstrap(path, endpoint)
	if err != nil {
		return environmentBootstrapFailure(*jsonOutput, "config_update_failed", fail(exitConfig, "%v", err))
	}

	if err := writeDockerBootstrapReview(os.Stderr, *socket, daemon); err != nil {
		return environmentBootstrapFailure(*jsonOutput, "output_failed", fail(exitFailure, "write endpoint review: %v", err))
	}
	if plan.Changed {
		fmt.Fprint(os.Stderr, plan.Diff(path))
	}
	if !*yes {
		if *nonInteractive || !configinit.IsTerminal(os.Stdin) {
			return environmentBootstrapFailure(*jsonOutput, "confirmation_required", fail(exitConfig, "bootstrap requires confirmation; rerun with explicit --socket PATH --yes"))
		}
		confirmed, confirmErr := promptConfirmation("Trust this Docker endpoint?")
		if confirmErr != nil {
			return environmentBootstrapFailure(*jsonOutput, "confirmation_failed", fail(exitConfig, "%v", confirmErr))
		}
		if !confirmed {
			return environmentBootstrapFailure(*jsonOutput, "cancelled", fail(exitConfig, "Docker endpoint bootstrap cancelled"))
		}
	}
	if err := plan.Apply(path); err != nil {
		return environmentBootstrapFailure(*jsonOutput, "config_update_failed", fail(exitConfig, "%v", err))
	}
	result := environmentBootstrapResult{Status: "trusted", Config: path, Socket: *socket, Daemon: daemon, Changed: plan.Changed}
	if *jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "environment bootstrap", Results: []environmentBootstrapResult{result},
			Summary:  map[string]any{"status": result.Status, "changed": result.Changed},
			Warnings: []string{}, Errors: []jsonCommandError{},
		})
	}
	fmt.Printf("trusted Docker endpoint: %s\n", *socket)
	fmt.Printf("updated protected config: %s\n", path)
	return nil
}

func writeDockerBootstrapReview(writer io.Writer, socket string, daemon config.DockerDaemonIdentity) error {
	if _, err := fmt.Fprintf(writer, "Docker endpoint review:\n  socket: %s\n  daemon_id: %s\n  server_version: %s\n  platform: %s/%s\n  api_version: %s\n  required_security_options:\n",
		socket, daemon.ID, daemon.ServerVersion, daemon.OperatingSystem, daemon.Architecture, daemon.MinimumAPIVersion); err != nil {
		return err
	}
	for _, option := range daemon.RequiredSecurityOptions {
		if _, err := fmt.Fprintf(writer, "    - %s\n", option); err != nil {
			return err
		}
	}
	return nil
}

func dockerSocketSuggestions() []string {
	var suggestions []string
	if runtime.GOOS == "linux" {
		suggestions = append(suggestions, "/var/run/docker.sock")
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		suggestions = append(suggestions,
			filepath.Join(home, ".docker", "run", "docker.sock"),
			filepath.Join(home, "Library", "Containers", "com.docker.docker", "Data", "docker.raw.sock"),
		)
	}
	return suggestions
}

func environmentBootstrapFailure(jsonOutput bool, code string, err error) error {
	return jsonCommandFailure(jsonOutput, "environment bootstrap", code, err, nil)
}
