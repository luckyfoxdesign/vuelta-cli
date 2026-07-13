//go:build unix

package pipeline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ProcessLock prevents overlapping `vuelta run` invocations, e.g. when an
// external timer fires again before the previous run finished (part B §7
// preamble: "под process-lock, чтобы таймеры не пересекались").
type ProcessLock struct {
	file *os.File
}

// AcquireProcessLock takes an exclusive, non-blocking flock on path. It
// returns an error if another vuelta run already holds the lock.
func AcquireProcessLock(path string) (*ProcessLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another vuelta run is already in progress (lock %s): %w", path, err)
	}
	return &ProcessLock{file: f}, nil
}

// Release unlocks and closes the lock file. Both the unlock and the close
// can fail independently (e.g. the fd is fine but the underlying file was
// removed from under us); callers should not silently drop this, since a
// lock that fails to release can make every subsequent `vuelta run` think
// one is already in progress.
func (l *ProcessLock) Release() error {
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	return errors.Join(unlockErr, closeErr)
}
