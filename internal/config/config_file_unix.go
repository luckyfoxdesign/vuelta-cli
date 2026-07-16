//go:build darwin || linux

package config

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// ReadSecureFile reads a Darwin/Linux config only after verifying that it is
// a regular non-symlink file, is owned by the process uid, and grants no
// permissions beyond 0600. The returned mode is safe to preserve on an atomic
// replacement.
func ReadSecureFile(path string) ([]byte, os.FileMode, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("stat config %s: %w", path, err)
	}
	if err := validateConfigFile(path, pathInfo, uint32(os.Geteuid())); err != nil {
		return nil, 0, err
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open config %s without following symlinks: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, 0, fmt.Errorf("open config %s: invalid file descriptor", path)
	}
	defer func() { _ = file.Close() }()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat opened config %s: %w", path, err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil, 0, fmt.Errorf("config %s changed while it was being opened", path)
	}
	if err := validateConfigFile(path, openedInfo, uint32(os.Geteuid())); err != nil {
		return nil, 0, err
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, fmt.Errorf("read config %s: %w", path, err)
	}
	return data, openedInfo.Mode().Perm(), nil
}

func validateConfigFile(path string, info os.FileInfo, processUID uint32) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config %s must be a regular file and must not be a symlink", path)
	}
	if info.Mode().Perm()&^os.FileMode(0o600) != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("config %s has unsafe permissions %04o, which are broader than 0600", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("config %s owner cannot be verified on this platform", path)
	}
	if stat.Uid != processUID {
		return fmt.Errorf("config %s must be owned by the current process uid", path)
	}
	return nil
}
