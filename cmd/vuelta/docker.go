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
	if cfg.Docker == nil {
		return fmt.Errorf("%w: docker.developer is required; run `vuelta environment bootstrap --socket PATH`", errDockerBootstrapRequired)
	}
	endpoint, err := configuredDockerEndpoint(cfg.Docker.Developer, "docker.developer")
	if err != nil {
		return err
	}
	dockerexec.ConfigureDefault(endpoint)
	return nil
}
