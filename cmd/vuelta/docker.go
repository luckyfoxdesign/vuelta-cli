package main

import (
	"errors"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

func configuredDockerEndpoint(endpoint *config.DockerEndpointConfig, label string) (dockerexec.Endpoint, error) {
	if endpoint == nil {
		return dockerexec.Endpoint{}, errors.New(label + " is required for Docker execution; configure an approved local socket and expected daemon identity")
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
		return errors.New("docker.developer is required for container execution; configure an approved local socket and expected daemon identity")
	}
	endpoint, err := configuredDockerEndpoint(cfg.Docker.Developer, "docker.developer")
	if err != nil {
		return err
	}
	dockerexec.ConfigureDefault(endpoint)
	return nil
}
