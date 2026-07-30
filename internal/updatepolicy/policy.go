// Package updatepolicy applies Vuelta's machine-owned delayed-latest policy to
// normalized, non-executable dependency metadata.
package updatepolicy

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// MinimumCooldown is the safe machine-owned default. Project policy may
	// lengthen it but cannot silently shorten it.
	MinimumCooldown = 14 * 24 * time.Hour

	ClassPatch      = "patch"
	ClassMinor      = "minor"
	ClassMajor      = "major"
	ClassUnknown    = "unknown"
	ClassPrerelease = "prerelease"

	DispositionRoutine  = "routine"
	DispositionDeferred = "deferred"
	DispositionExcluded = "excluded"
)

// Candidate is the version metadata required for a policy decision.
type Candidate struct {
	Current         string
	Target          string
	Direct          bool
	Yanked          bool
	PublicationTime time.Time
	FirstObservedAt time.Time
	AgeVerified     bool
}

// Decision is persisted and included in update requests.
type Decision struct {
	VersionClass    string
	Stable          bool
	FirstObservedAt time.Time
	EligibleAt      time.Time
	Disposition     string
	Reason          string
}

// Evaluate classifies one candidate conservatively. Unknown version syntax,
// pre-releases, yanked releases, transitive dependencies, majors, and releases
// still in cooldown never enter the routine set.
func Evaluate(now time.Time, cooldown time.Duration, candidate Candidate) Decision {
	now = now.UTC()
	if cooldown < MinimumCooldown {
		cooldown = MinimumCooldown
	}
	firstObserved := candidate.FirstObservedAt.UTC()
	if firstObserved.IsZero() {
		firstObserved = now
	}
	eligibleBase := firstObserved
	if !candidate.PublicationTime.IsZero() {
		eligibleBase = candidate.PublicationTime.UTC()
	}
	eligibleAt := eligibleBase.Add(cooldown)
	if candidate.AgeVerified && candidate.PublicationTime.IsZero() {
		// The scanner proved the release already passed the complete cooldown
		// but did not expose an authoritative publication timestamp. The first
		// safe eligibility instant Vuelta can persist is this observation.
		eligibleAt = now
	}
	class, stable := classify(candidate.Current, candidate.Target)
	decision := Decision{
		VersionClass: class, Stable: stable, FirstObservedAt: firstObserved,
		EligibleAt: eligibleAt, Disposition: DispositionDeferred,
	}
	switch {
	case candidate.Yanked:
		decision.Disposition, decision.Reason = DispositionExcluded, "yanked"
	case !stable:
		decision.Disposition, decision.Reason = DispositionExcluded, class
	case !candidate.Direct:
		decision.Reason = "transitive"
	case class == ClassMajor:
		decision.Reason = "major"
	case class == ClassUnknown:
		decision.Reason = "unknown_version_change"
	case now.Before(eligibleAt) && !candidate.AgeVerified:
		decision.Reason = "cooldown"
	case class == ClassPatch || class == ClassMinor:
		decision.Disposition, decision.Reason = DispositionRoutine, "eligible"
	default:
		decision.Reason = "not_routine"
	}
	return decision
}

var stableVersionPattern = regexp.MustCompile(`^[vV]?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:\.([0-9]+))?$`)

type version struct {
	parts [4]int
	count int
}

func classify(current, target string) (string, bool) {
	if looksPrerelease(target) {
		return ClassPrerelease, false
	}
	from, fromOK := parseStable(current)
	to, toOK := parseStable(target)
	if !toOK {
		return ClassUnknown, false
	}
	if !fromOK {
		return ClassUnknown, true
	}
	switch {
	case from.parts[0] != to.parts[0]:
		return ClassMajor, true
	case from.parts[1] != to.parts[1]:
		return ClassMinor, true
	case from.parts[2] != to.parts[2] || from.parts[3] != to.parts[3]:
		return ClassPatch, true
	default:
		return ClassUnknown, true
	}
}

func parseStable(value string) (version, bool) {
	match := stableVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return version{}, false
	}
	result := version{count: len(match) - 1}
	for index, part := range match[1:] {
		if part == "" {
			continue
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || number > 1_000_000_000 {
			return version{}, false
		}
		result.parts[index] = number
	}
	return result, true
}

func looksPrerelease(value string) bool {
	lower := strings.ToLower(value)
	if strings.ContainsAny(lower, "+") {
		return true
	}
	for _, marker := range []string{"-", "alpha", "beta", "preview", "pre", "rc", "dev", "snapshot"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
