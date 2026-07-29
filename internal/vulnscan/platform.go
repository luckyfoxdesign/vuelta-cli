package vulnscan

import (
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
)

// ScannerPlatformError reports that the selected scanner image cannot run on
// the approved Docker runtime platform. It intentionally carries no wrapped
// command error so public diagnostics cannot expose image references, command
// arguments, or registry output.
type ScannerPlatformError struct{}

func (*ScannerPlatformError) Error() string {
	return "scanner image is incompatible with the Docker runtime platform"
}

func isScannerPlatformMismatch(err error) bool {
	if err == nil {
		return false
	}
	_, _, detail := dockerexec.Classify(err)
	if detail == "" {
		detail = safeerr.Excerpt([]byte(err.Error()), 1024)
	}
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "exec format error"):
		return true
	case strings.Contains(lower, "no matching manifest for") &&
		strings.Contains(lower, "manifest list"):
		return true
	case strings.Contains(lower, "no match for platform in manifest"):
		return true
	case strings.Contains(lower, "does not match the specified platform"):
		return true
	case strings.Contains(lower, "requested image's platform") &&
		strings.Contains(lower, "does not match"):
		return true
	default:
		return false
	}
}
