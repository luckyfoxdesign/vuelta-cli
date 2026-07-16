//go:build windows

package gitexec

import "os"

func validateOwner(os.FileInfo) error { return nil }
