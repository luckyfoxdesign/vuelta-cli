// Package gitpath defines platform-independent matching for Git repository paths.
package gitpath

import (
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

// ValidatePattern checks a repository-relative allowlist pattern. Patterns use
// slash separators on every platform and path.Match syntax: *, ?, and [] match
// only within one path segment. Recursive ** matching is deliberately unsupported.
func ValidatePattern(pattern string) error {
	if err := validateCommon(pattern, "pattern"); err != nil {
		return err
	}
	if strings.Contains(pattern, "**") {
		return errorsf("pattern", pattern, "recursive ** globs are not supported")
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return errorsf("pattern", pattern, "invalid glob syntax: %v", err)
	}
	return nil
}

// ValidatePath checks that value is a normalized Git repository-relative path.
func ValidatePath(value string) error {
	return validateCommon(value, "path")
}

// Allowed reports whether repository-relative value matches one of patterns.
// It validates both the path and every pattern so invalid policy fails closed.
func Allowed(value string, patterns []string) (bool, error) {
	if err := ValidatePath(value); err != nil {
		return false, err
	}
	for _, pattern := range patterns {
		if err := ValidatePattern(pattern); err != nil {
			return false, err
		}
		matched, err := path.Match(pattern, value)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// ValidatePatterns checks all configured allowlist patterns.
func ValidatePatterns(patterns []string) error {
	for _, pattern := range patterns {
		if err := ValidatePattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

func validateCommon(value, kind string) error {
	if value == "" {
		return errorsf(kind, value, "must not be empty")
	}
	if !utf8.ValidString(value) {
		return errorsf(kind, value, "must be valid UTF-8")
	}
	if strings.ContainsRune(value, '\x00') {
		return errorsf(kind, value, "must not contain NUL")
	}
	if strings.Contains(value, `\`) {
		return errorsf(kind, value, "must use Git-style slash separators")
	}
	if strings.HasPrefix(value, "/") || hasDrivePrefix(value) {
		return errorsf(kind, value, "must be repository-relative")
	}
	if path.Clean(value) != value || value == "." {
		return errorsf(kind, value, "must be normalized without empty, dot, or traversal segments")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return errorsf(kind, value, "must not contain dot or traversal segments")
		}
	}
	return nil
}

func hasDrivePrefix(value string) bool {
	return len(value) >= 2 && value[1] == ':' &&
		((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z'))
}

func errorsf(kind, value, format string, args ...any) error {
	return fmt.Errorf("git %s %q: %s", kind, value, fmt.Sprintf(format, args...))
}
