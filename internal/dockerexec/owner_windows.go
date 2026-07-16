//go:build windows

package dockerexec

import "os"

func validateOwner(os.FileInfo) error { return nil }
