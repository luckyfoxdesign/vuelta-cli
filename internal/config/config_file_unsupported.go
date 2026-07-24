//go:build !darwin && !linux

package config

import (
	"fmt"
	"os"
)

// ReadSecureFile rejects unsupported operating systems. Vuelta's config-file
// security contract currently targets Darwin and Linux only.
func ReadSecureFile(path string) ([]byte, os.FileMode, error) {
	return nil, 0, fmt.Errorf("read config %s: unsupported operating system; vuelta config requires Darwin or Linux", path)
}

// ReadProjectFile rejects unsupported operating systems.
func ReadProjectFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("read project config %s: unsupported operating system; vuelta project config requires Darwin or Linux", path)
}
