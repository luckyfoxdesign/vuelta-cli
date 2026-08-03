package ecosystem

import (
	"regexp"
	"strconv"
	"strings"
)

var candidateVersionPattern = regexp.MustCompile(`^[vV]?([0-9]+(?:\.[0-9]+){0,3})([-+][A-Za-z0-9][A-Za-z0-9.+-]*)?$`)

// NormalizeCandidateVersion canonicalizes the bounded numeric version syntax
// shared by the built-in package adapters. Unknown ecosystem-specific syntax
// is preserved after surrounding whitespace is removed.
func NormalizeCandidateVersion(value string) string {
	trimmed := strings.TrimSpace(value)
	match := candidateVersionPattern.FindStringSubmatch(trimmed)
	if match == nil {
		return trimmed
	}
	parts := strings.Split(match[1], ".")
	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return trimmed
		}
		parts[index] = strconv.FormatUint(number, 10)
	}
	return strings.Join(parts, ".") + match[2]
}

// CandidateVersionsEqual reports whether current and target describe the same
// normalized release. Missing current versions are never treated as no-ops.
func CandidateVersionsEqual(current, target string) bool {
	if strings.TrimSpace(current) == "" {
		return false
	}
	current = NormalizeCandidateVersion(current)
	target = NormalizeCandidateVersion(target)
	if current == target {
		return true
	}
	currentParts, currentOK := numericCandidateVersion(current)
	targetParts, targetOK := numericCandidateVersion(target)
	return currentOK && targetOK && currentParts == targetParts
}

func numericCandidateVersion(value string) ([4]uint64, bool) {
	match := candidateVersionPattern.FindStringSubmatch(value)
	if match == nil || match[2] != "" {
		return [4]uint64{}, false
	}
	var result [4]uint64
	for index, part := range strings.Split(match[1], ".") {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return [4]uint64{}, false
		}
		result[index] = number
	}
	return result, true
}
