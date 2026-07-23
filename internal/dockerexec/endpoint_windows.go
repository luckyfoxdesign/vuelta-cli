//go:build windows

package dockerexec

import "errors"

func validateEndpoint(Endpoint) (string, error) {
	return "", errors.New("approved Docker Unix socket endpoints are not supported on Windows")
}

func validateProbeEndpoint(Endpoint) (string, error) {
	return "", errors.New("Docker Unix socket onboarding is not supported on Windows")
}
