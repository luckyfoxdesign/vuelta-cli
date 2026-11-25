package main

import (
	"errors"
	"fmt"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

var errDockerBootstrapRequired = errors.New("trusted Docker endpoint bootstrap is required")

func configuredDockerEndpoint(endpoint *config.DockerEndpointConfig, label string) (dockerexec.Endpoint, error) {
	if endpoint == nil {
		return dockerexec.Endpoint{}, fmt.Errorf("%w: %s is required; run `vuelta environment bootstrap --socket PATH`", errDockerBootstrapRequired, label)
	}
	expected := endpoint.ExpectedDaemon
	return dockerexec.Endpoint{
		SocketPath: endpoint.Socket,
		Expected: dockerexec.DaemonIdentity{
			ID: expected.ID, ServerVersion: expected.ServerVersion,
			OperatingSystem: expected.OperatingSystem, Architecture: expected.Architecture,
			MinimumAPIVersion:       expected.MinimumAPIVersion,
			RequiredSecurityOptions: append([]string(nil), expected.RequiredSecurityOptions...),
		},
	}, nil
}

func configureDeveloperDocker(cfg config.Config) error {
	endpoints, err := configuredDeveloperDockerEndpoints(cfg)
	if err != nil {
		return err
	}
	dockerexec.ConfigureDefault(endpoints...)
	return nil
}

func configuredDeveloperDockerEndpoints(cfg config.Config) ([]dockerexec.Endpoint, error) {
	trusted := cfg.Docker.TrustedDeveloperEndpoints()
	if len(trusted) == 0 {
		return nil, fmt.Errorf("%w: docker.developer_endpoints is required; run `vuelta environment bootstrap --socket PATH`", errDockerBootstrapRequired)
	}
	var endpoints []dockerexec.Endpoint
	for i := range trusted {
		endpoint, err := configuredDockerEndpoint(&trusted[i], "docker.developer_endpoints")
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func selectedDeveloperDockerSocket() (string, error) {
	executor, ok := dockerexec.Default().(*dockerexec.Executor)
	if !ok {
		return "", errors.New("docker executor cannot report its selected endpoint")
	}
	return executor.SocketPath()
}

func configuredCleanupEndpoint(cfg config.Config, socket string) (dockerexec.Endpoint, error) {
	for _, endpoint := range cfg.Docker.TrustedDeveloperEndpoints() {
		if endpoint.Socket == socket {
			return configuredDockerEndpoint(&endpoint, "cleanup Docker endpoint")
		}
	}
	return dockerexec.Endpoint{}, errors.New("cleanup guardian socket is not a trusted Docker endpoint")
}
