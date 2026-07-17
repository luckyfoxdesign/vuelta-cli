//go:build !unix

package scaninput

import "os"

func sameOwner(_, _ os.FileInfo) bool            { return true }
func hasMultipleLinks(_ os.FileInfo) bool        { return false }
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
