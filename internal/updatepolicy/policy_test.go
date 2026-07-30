package updatepolicy

import (
	"testing"
	"time"
)

func TestEvaluateRoutineAndDeferredBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		candidate   Candidate
		disposition string
		class       string
	}{
		{
			name: "eligible patch", candidate: Candidate{
				Current: "1.2.3", Target: "1.2.4", Direct: true,
				FirstObservedAt: now.Add(-MinimumCooldown),
			},
			disposition: DispositionRoutine, class: ClassPatch,
		},
		{
			name: "eligible minor", candidate: Candidate{
				Current: "1.2.3", Target: "1.3.0", Direct: true,
				PublicationTime: now.Add(-MinimumCooldown),
			},
			disposition: DispositionRoutine, class: ClassMinor,
		},
		{
			name: "cooldown boundary", candidate: Candidate{
				Current: "1.2.3", Target: "1.2.4", Direct: true,
				FirstObservedAt: now.Add(-MinimumCooldown + time.Nanosecond),
			},
			disposition: DispositionDeferred, class: ClassPatch,
		},
		{
			name: "major", candidate: Candidate{
				Current: "1.2.3", Target: "2.0.0", Direct: true,
				FirstObservedAt: now.Add(-MinimumCooldown),
			},
			disposition: DispositionDeferred, class: ClassMajor,
		},
		{
			name: "transitive", candidate: Candidate{
				Current: "1.2.3", Target: "1.2.4",
				FirstObservedAt: now.Add(-MinimumCooldown),
			},
			disposition: DispositionDeferred, class: ClassPatch,
		},
		{
			name: "prerelease", candidate: Candidate{
				Current: "1.2.3", Target: "1.3.0-rc.1", Direct: true,
				FirstObservedAt: now.Add(-MinimumCooldown),
			},
			disposition: DispositionExcluded, class: ClassPrerelease,
		},
		{
			name: "yanked", candidate: Candidate{
				Current: "1.2.3", Target: "1.2.4", Direct: true, Yanked: true,
				FirstObservedAt: now.Add(-MinimumCooldown),
			},
			disposition: DispositionExcluded, class: ClassPatch,
		},
		{
			name: "verified by authoritative scanner", candidate: Candidate{
				Current: "1.2.3", Target: "1.2.4", Direct: true,
				FirstObservedAt: now, AgeVerified: true,
			},
			disposition: DispositionRoutine, class: ClassPatch,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			decision := Evaluate(now, MinimumCooldown, testCase.candidate)
			if decision.Disposition != testCase.disposition || decision.VersionClass != testCase.class {
				t.Fatalf("decision = %#v, want disposition=%s class=%s", decision, testCase.disposition, testCase.class)
			}
		})
	}
}

func TestEvaluateProjectCannotShortenCooldown(t *testing.T) {
	now := time.Now().UTC()
	decision := Evaluate(now, time.Hour, Candidate{
		Current: "1.0.0", Target: "1.0.1", Direct: true,
		FirstObservedAt: now.Add(-24 * time.Hour),
	})
	if decision.Disposition != DispositionDeferred {
		t.Fatalf("short cooldown was accepted: %#v", decision)
	}
}
