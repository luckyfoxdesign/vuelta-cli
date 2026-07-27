package ecosystem

import (
	"errors"
	"testing"
)

func TestResolveRuntimeSelectsHighestCompatibleProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		stack      string
		constraint string
		fallback   string
		supported  []string
		want       string
	}{
		{
			name: "exact Node patch intersects major profile", stack: "node",
			constraint: "24.7.0", fallback: "22", supported: []string{"22", "24", "20"}, want: "24",
		},
		{
			name: "Node lower bound selects highest profile", stack: "node",
			constraint: ">=18.0.0", fallback: "22", supported: []string{"22", "24", "20"}, want: "24",
		},
		{
			name: "Poetry caret selects highest Python profile", stack: "python",
			constraint: "^3.9", fallback: "3.12", supported: []string{"3.12", "3.13", "3.11"}, want: "3.13",
		},
		{
			name: "upper bound excludes newest Node profile", stack: "node",
			constraint: ">=20, <24", fallback: "22", supported: []string{"24", "20", "22"}, want: "22",
		},
		{
			name: "major exclusion is honored", stack: "node",
			constraint: ">=20 !=24.x", fallback: "22", supported: []string{"20", "24", "22"}, want: "22",
		},
		{
			name: "Python minor exclusion is honored", stack: "python",
			constraint: ">=3.11, !=3.13.*", fallback: "3.12", supported: []string{"3.11", "3.13", "3.12"}, want: "3.12",
		},
		{
			name: "tilde stays within the selected minor line", stack: "python",
			constraint: "~3.11.4", fallback: "3.12", supported: []string{"3.13", "3.11", "3.12"}, want: "3.11",
		},
		{
			name: "Python compatible release operator", stack: "python",
			constraint: "~=3.11.2", fallback: "3.12", supported: []string{"3.13", "3.11", "3.12"}, want: "3.11",
		},
		{
			name: "whitespace and leading v are normalized", stack: "node",
			constraint: "  >= v20.0.0,   < v23.0.0  ", fallback: "22", supported: []string{"20", "24", "22"}, want: "22",
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got, err := ResolveRuntime(
				testCase.stack,
				testCase.constraint,
				testCase.fallback,
				testCase.supported,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got != testCase.want {
				t.Fatalf("ResolveRuntime() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestResolveRuntimeIsIndependentOfSupportedInputOrder(t *testing.T) {
	t.Parallel()
	permutations := [][]string{
		{"20", "22", "24"},
		{"20", "24", "22"},
		{"22", "20", "24"},
		{"22", "24", "20"},
		{"24", "20", "22"},
		{"24", "22", "20"},
	}
	for _, supported := range permutations {
		got, err := ResolveRuntime("node", ">=18", "22", supported)
		if err != nil {
			t.Fatal(err)
		}
		if got != "24" {
			t.Fatalf("ResolveRuntime(%v) = %q, want 24", supported, got)
		}
	}
}

func TestParseRuntimeConstraintCanonicalizesBoundedGrammar(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stack string
		raw   string
		want  string
	}{
		{stack: "node", raw: "24.7.0", want: "=24.7.0"},
		{stack: "node", raw: "24.x", want: ">=24.0.0 <25.0.0"},
		{stack: "python", raw: "^3.9", want: ">=3.9.0 <4.0.0"},
		{stack: "python", raw: "~3.12", want: ">=3.12.0 <3.13.0"},
		{stack: "python", raw: "~=3.11.2", want: ">=3.11.2 <3.12.0"},
		{stack: "python", raw: ">=3.11, <3.14, !=3.12.*", want: ">=3.11.0 <3.14.0 !=3.12.x"},
	}
	for _, testCase := range tests {
		parsed, err := ParseRuntimeConstraint(testCase.stack, testCase.raw)
		if err != nil {
			t.Fatalf("ParseRuntimeConstraint(%q): %v", testCase.raw, err)
		}
		if parsed.Canonical() != testCase.want {
			t.Fatalf("ParseRuntimeConstraint(%q) = %q, want %q", testCase.raw, parsed.Canonical(), testCase.want)
		}
	}
}

func TestRuntimeConstraintErrorsAreTyped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		stack      string
		constraint string
		wantCode   string
	}{
		{
			name: "malformed value", stack: "node", constraint: ">=twenty",
			wantCode: RuntimeConstraintInvalid,
		},
		{
			name: "numeric component after wildcard", stack: "node", constraint: "24.x.1",
			wantCode: RuntimeConstraintInvalid,
		},
		{
			name: "union", stack: "node", constraint: ">=20 || >=24",
			wantCode: RuntimeConstraintUnsupportedSyntax,
		},
		{
			name: "hyphen range", stack: "python", constraint: "3.9 - 3.13",
			wantCode: RuntimeConstraintUnsupportedSyntax,
		},
		{
			name: "Python-only operator in Node constraint", stack: "node", constraint: "~=20.0",
			wantCode: RuntimeConstraintUnsupportedSyntax,
		},
		{
			name: "incompatible exact version", stack: "node", constraint: "25.0.0",
			wantCode: RuntimeConstraintNoCompatible,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := ResolveRuntime(
				testCase.stack,
				testCase.constraint,
				map[string]string{"node": "22", "python": "3.12"}[testCase.stack],
				map[string][]string{
					"node":   {"20", "22", "24"},
					"python": {"3.11", "3.12", "3.13"},
				}[testCase.stack],
			)
			var constraintErr *RuntimeConstraintError
			if !errors.As(err, &constraintErr) {
				t.Fatalf("ResolveRuntime() error = %T %v", err, err)
			}
			if constraintErr.ReasonCode != testCase.wantCode {
				t.Fatalf("error code = %q, want %q", constraintErr.ReasonCode, testCase.wantCode)
			}
			if constraintErr.Hint() == "" {
				t.Fatal("typed error has no actionable hint")
			}
		})
	}
}

func TestRuntimeConstraintNeverMatchesOutsideConstraint(t *testing.T) {
	t.Parallel()
	parsed, err := ParseRuntimeConstraint("python", ">=3.11,<3.13,!=3.12.*")
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.MatchesProfile("3.11") {
		t.Fatal("compatible Python 3.11 profile was rejected")
	}
	for _, runtime := range []string{"3.10", "3.12", "3.13"} {
		if parsed.MatchesProfile(runtime) {
			t.Fatalf("runtime %s matched outside the parsed constraint", runtime)
		}
	}
}
