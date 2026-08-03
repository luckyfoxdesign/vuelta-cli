package ecosystem

import "testing"

func TestCandidateVersionNormalizationAndEquality(t *testing.T) {
	tests := []struct {
		name       string
		current    string
		target     string
		normalized string
		equal      bool
	}{
		{name: "leading v", current: "v4.0.3", target: "4.0.3", normalized: "4.0.3", equal: true},
		{name: "missing numeric components", current: "4.0.3.0", target: "4.0.3", normalized: "4.0.3", equal: true},
		{name: "leading zeroes", current: "04.00.003", target: "4.0.3", normalized: "4.0.3", equal: true},
		{name: "real update", current: "4.0.3", target: "4.0.4", normalized: "4.0.4", equal: false},
		{name: "ecosystem syntax preserved", current: "1.0rc1", target: "1.0", normalized: "1.0", equal: false},
		{name: "missing current", current: "", target: "1.0.0", normalized: "1.0.0", equal: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := NormalizeCandidateVersion(testCase.target); got != testCase.normalized {
				t.Fatalf("NormalizeCandidateVersion(%q) = %q, want %q", testCase.target, got, testCase.normalized)
			}
			if got := CandidateVersionsEqual(testCase.current, testCase.target); got != testCase.equal {
				t.Fatalf("CandidateVersionsEqual(%q, %q) = %t, want %t", testCase.current, testCase.target, got, testCase.equal)
			}
		})
	}
}
