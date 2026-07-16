package gitexec

import (
	"errors"
	"regexp"
	"strings"
)

var (
	remoteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	commitPattern     = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ValidateRemoteName rejects option-like or URL-shaped remote arguments.
// Network operations accept only a configured remote name; Git's protocol
// policy independently rejects transports outside file/https/ssh.
func ValidateRemoteName(value string) error {
	if !remoteNamePattern.MatchString(value) {
		return errors.New("git remote name is invalid")
	}
	return nil
}

// ValidateCommitSHA accepts only a complete SHA-1 or SHA-256 object name.
func ValidateCommitSHA(value string) error {
	if !commitPattern.MatchString(value) {
		return errors.New("git commit must be a full lowercase object ID")
	}
	return nil
}

// ValidateBranch accepts a normalized branch path suitable below refs/heads.
func ValidateBranch(value string) error { return validateRefPart(value, "branch") }

// ValidateTag accepts a normalized tag path suitable below refs/tags.
func ValidateTag(value string) error { return validateRefPart(value, "tag") }

func validateRefPart(value, kind string) error {
	if value == "" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, ".") ||
		strings.HasPrefix(value, "refs/") ||
		strings.HasSuffix(value, ".") || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "..") || strings.Contains(value, "@{") ||
		strings.Contains(value, "//") || strings.ContainsAny(value, " \t\r\n~^:?*[\\") {
		return errors.New("git " + kind + " is invalid")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".lock") {
			return errors.New("git " + kind + " is invalid")
		}
	}
	return nil
}
