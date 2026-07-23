// Package safeerr builds safe, bounded, redacted diagnostic text and stable
// failure categories for hardened command boundaries.
// It only ever operates on output a boundary already captured under its own
// size limits; it never sees full argv, environment, or unbounded output.
package safeerr

import (
	"regexp"
	"strings"
)

// Category is a stable, safe failure classification safe to surface in CLI
// output and structured JSON.
type Category string

const (
	CategoryTimeout         Category = "timeout"
	CategoryCancelled       Category = "cancelled"
	CategoryOutputLimit     Category = "output_limit"
	CategoryPermission      Category = "permission"
	CategoryEndpoint        Category = "endpoint"
	CategoryEgress          Category = "egress"
	CategoryImagePlatform   Category = "image_platform"
	CategoryUnsupportedFlag Category = "unsupported_flag"
	CategoryUnknown         Category = "unknown"
)

// credentialLike matches common credential-bearing shapes: "key: value" /
// "key=value" assignments for key/secret/token/password names, bearer
// tokens, Authorization headers, and userinfo embedded in URLs.
var credentialLike = regexp.MustCompile(`(?i)(authorization\s*:\s*.*|bearer\s+\S+|(api[_-]?key|secret|token|password)\s*[:=]\s*\S+|://[^/\s:@]+:[^/\s@]+@)`)

// Redact masks credential-like substrings in already-bounded diagnostic
// text. It is not a general-purpose secret scanner; it is a best-effort
// safety net for text a hardened boundary is about to surface.
func Redact(text string) string {
	return credentialLike.ReplaceAllString(text, "<redacted>")
}

// Tail returns a redacted, trimmed diagnostic tail no longer than max bytes,
// suitable for safe display alongside a stable failure category.
func Tail(data []byte, max int) string {
	text := Redact(strings.TrimSpace(string(data)))
	if max <= 0 || len(text) <= max {
		return text
	}
	return text[len(text)-max:]
}

// ClassifyDetail derives a stable, safe category from already-redacted
// diagnostic text using conservative substring heuristics. It returns
// CategoryUnknown when the text gives no reliable signal.
func ClassifyDetail(detail string) Category {
	lower := strings.ToLower(detail)
	switch {
	case detail == "":
		return CategoryUnknown
	case strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted"):
		return CategoryPermission
	case strings.Contains(lower, "no matching manifest") || strings.Contains(lower, "no such platform") ||
		(strings.Contains(lower, "platform") && strings.Contains(lower, "image")):
		return CategoryImagePlatform
	case strings.Contains(lower, "proxy") || strings.Contains(lower, "connect tunnel") || strings.Contains(lower, "econnrefused"):
		return CategoryEgress
	case strings.Contains(lower, "no such host") || strings.Contains(lower, "lookup ") ||
		strings.Contains(lower, "dial tcp") || strings.Contains(lower, "connection refused"):
		return CategoryEndpoint
	case strings.Contains(lower, "unknown flag") || strings.Contains(lower, "unrecognized") ||
		strings.Contains(lower, "unknown option") || strings.Contains(lower, "flag provided but not defined"):
		return CategoryUnsupportedFlag
	default:
		return CategoryUnknown
	}
}
