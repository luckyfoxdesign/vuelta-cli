//go:build !darwin && !linux

package projectstate

import (
	"fmt"
	"io"
	"os"
)

func readBoundedNoFollow(path, label string, initial os.FileInfo, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened %s: %w", label, err)
	}
	if !os.SameFile(initial, opened) {
		return nil, fmt.Errorf("%s changed while it was being opened", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return data, nil
}
