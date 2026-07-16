//go:build !windows

package dockerexec

import (
	"errors"
	"os"
	"syscall"
)

func validateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify approved Docker CLI owner")
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != uid {
		return errors.New("approved Docker CLI is not owned by root or the current user")
	}
	return nil
}
