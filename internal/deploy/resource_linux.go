//go:build linux

package deploy

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func hostResources(path string) (HostResources, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return HostResources{}, fmt.Errorf("read memory availability: %w", err)
	}
	defer func() { _ = file.Close() }()

	var availableKB uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			availableKB, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return HostResources{}, errors.New("parse memory availability")
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return HostResources{}, fmt.Errorf("read memory availability: %w", err)
	}
	if availableKB == 0 {
		return HostResources{}, errors.New("memory availability is unavailable")
	}

	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil {
		return HostResources{}, fmt.Errorf("read disk availability: %w", err)
	}
	const bytesPerMiB = 1024 * 1024
	freeDiskMB := (stats.Bavail * uint64(stats.Bsize)) / bytesPerMiB
	return HostResources{
		FreeMemoryMB: boundedResourceMB(availableKB / 1024),
		FreeDiskMB:   boundedResourceMB(freeDiskMB),
	}, nil
}

func boundedResourceMB(value uint64) int {
	maxInt := uint64(^uint(0) >> 1)
	if value > maxInt {
		return int(maxInt)
	}
	return int(value)
}
