//go:build !windows

package dockerexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func validateEndpoint(endpoint Endpoint) (string, error) {
	canonical, err := validateProbeEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	if err := validateExpectedIdentity(endpoint.Expected); err != nil {
		return "", err
	}
	return canonical, nil
}

func validateProbeEndpoint(endpoint Endpoint) (string, error) {
	if endpoint.SocketPath == "" {
		return "", errors.New("explicit Docker socket is required")
	}
	if !filepath.IsAbs(endpoint.SocketPath) || strings.ContainsRune(endpoint.SocketPath, '\x00') {
		return "", errors.New("approved Docker socket must be an absolute local path")
	}
	canonical, err := filepath.EvalSymlinks(endpoint.SocketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", &EndpointUnavailableError{Err: errors.New("approved Docker socket does not exist")}
		}
		return "", errors.New("approved Docker socket is inaccessible")
	}
	info, err := os.Stat(canonical)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return "", errors.New("approved Docker endpoint is not a Unix socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot verify approved Docker socket owner")
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != uid {
		return "", errors.New("approved Docker socket is not owned by root or the current user")
	}
	if info.Mode().Perm()&0o002 != 0 {
		return "", errors.New("approved Docker socket is writable by other users")
	}
	for parent := filepath.Dir(canonical); ; parent = filepath.Dir(parent) {
		parentInfo, statErr := os.Stat(parent)
		if statErr != nil {
			return "", errors.New("cannot inspect approved Docker socket parent directory")
		}
		parentStat, statOK := parentInfo.Sys().(*syscall.Stat_t)
		if !statOK || (parentStat.Uid != 0 && parentStat.Uid != uid) {
			return "", errors.New("approved Docker socket parent is not owned by root or the current user")
		}
		if parentInfo.Mode().Perm()&0o022 != 0 {
			return "", errors.New("approved Docker socket parent is writable by group or other")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return canonical, nil
}

func validateExpectedIdentity(identity DaemonIdentity) error {
	if strings.TrimSpace(identity.ID) == "" || strings.TrimSpace(identity.ServerVersion) == "" ||
		strings.TrimSpace(identity.OperatingSystem) == "" || strings.TrimSpace(identity.Architecture) == "" {
		return errors.New("approved Docker daemon ID, server version, OS, and architecture are required")
	}
	if compareAPIVersions(identity.MinimumAPIVersion, identity.MinimumAPIVersion) != 0 {
		return errors.New("approved Docker minimum API version must use major.minor format")
	}
	if len(identity.RequiredSecurityOptions) == 0 {
		return errors.New("approved Docker daemon requires at least one expected security option")
	}
	seen := make(map[string]bool, len(identity.RequiredSecurityOptions))
	for _, option := range identity.RequiredSecurityOptions {
		if strings.TrimSpace(option) == "" || seen[option] {
			return fmt.Errorf("approved Docker daemon has an invalid required security option %q", option)
		}
		seen[option] = true
	}
	return nil
}
