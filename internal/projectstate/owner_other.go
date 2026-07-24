//go:build !unix

package projectstate

import "os"

func ownedByCurrentUser(_ os.FileInfo) bool {
	// The supported production targets are Unix. Keep type/mode checks on
	// other build targets where a portable ownership API is unavailable.
	return true
}
