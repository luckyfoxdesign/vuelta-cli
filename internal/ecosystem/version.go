package ecosystem

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var comparatorPattern = regexp.MustCompile(`(>=|<=|>|<|\^|~|=)?\s*v?([0-9]+(?:\.[0-9]+)?)`)

// ResolveRuntime selects a supported runtime without executing project code.
func ResolveRuntime(stack, constraint, fallback string, supported []string) (string, error) {
	if strings.TrimSpace(constraint) == "" {
		return fallback, nil
	}
	for _, candidate := range supported {
		if VersionMatches(candidate, constraint) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("runtime constraint %q is unsupported; supported %s runtimes are %s; add an update.toolchain_profiles override for an exception", constraint, stack, strings.Join(supported, ", "))
}

// VersionMatches implements the bounded runtime constraint behavior used by
// built-in adapters and profile compatibility checks.
func VersionMatches(version, constraint string) bool {
	actual, ok := numericVersion(version)
	if !ok {
		return false
	}
	for _, alternative := range strings.Split(constraint, "||") {
		matches := comparatorPattern.FindAllStringSubmatch(alternative, -1)
		if len(matches) == 0 {
			continue
		}
		allowed := true
		for _, match := range matches {
			expected, valid := numericVersion(match[2])
			if !valid || !compareVersion(actual, expected, match[1]) {
				allowed = false
				break
			}
		}
		if allowed {
			return true
		}
	}
	return false
}

func numericVersion(value string) ([2]int, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
	if len(parts) == 0 || len(parts) > 2 {
		return [2]int{}, false
	}
	var result [2]int
	for index, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return [2]int{}, false
		}
		result[index] = n
	}
	return result, true
}

func compareVersion(actual, expected [2]int, operator string) bool {
	cmp := 0
	if actual[0] != expected[0] {
		if actual[0] < expected[0] {
			cmp = -1
		} else {
			cmp = 1
		}
	} else if actual[1] != expected[1] {
		if actual[1] < expected[1] {
			cmp = -1
		} else {
			cmp = 1
		}
	}
	switch operator {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "^", "~", "", "=":
		return actual[0] == expected[0] && (strings.Contains(operator, "~") || expected[1] == 0 || actual[1] == expected[1])
	default:
		return false
	}
}
