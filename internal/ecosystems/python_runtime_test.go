package ecosystems

import (
	"errors"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestPythonRuntimePolicyIsCompleteAndDefensive(t *testing.T) {
	t.Parallel()
	releases, fallback := PythonRuntimePolicy()
	if len(releases) == 0 {
		t.Fatal("Python runtime policy is empty")
	}
	if fallback != "3.12" {
		t.Fatalf("fallback = %q, want 3.12", fallback)
	}
	eolPattern := regexp.MustCompile(`^20[0-9]{2}-(?:0[1-9]|1[0-2])$`)
	families := make([]string, 0, len(releases))
	for _, release := range releases {
		if release.Family == "" || release.Lifecycle == "" || !eolPattern.MatchString(release.UpstreamEOL) {
			t.Fatalf("invalid reviewed release metadata: %#v", release)
		}
		families = append(families, release.Family)
	}
	if !slices.IsSorted(families) {
		t.Fatalf("runtime families are not ordered oldest-to-newest: %v", families)
	}
	if !slices.Contains(families, fallback) {
		t.Fatalf("fallback %q is not in supported families %v", fallback, families)
	}
	if !slices.Contains(families, "3.10") || !slices.Contains(families, "3.14") {
		t.Fatalf("boundary runtime families are missing: %v", families)
	}

	releases[0].Family = "mutated"
	got, _ := PythonRuntimePolicy()
	if got[0].Family == "mutated" {
		t.Fatal("caller mutated the embedded Python runtime policy")
	}
}

func TestResolvePythonRuntimeUsesReviewedPolicy(t *testing.T) {
	t.Parallel()
	_, fallback := PythonRuntimePolicy()
	tests := []struct {
		name       string
		constraint string
		want       string
	}{
		{name: "empty uses declared fallback", want: fallback},
		{name: "old boundary", constraint: "3.10.*", want: "3.10"},
		{name: "new boundary", constraint: "3.14.*", want: "3.14"},
		{name: "complete range selects newest", constraint: ">=3.10,<3.15", want: "3.14"},
		{name: "upper bound and exclusion", constraint: "<3.14,!=3.13.*", want: "3.12"},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolvePythonRuntime(testCase.constraint)
			if err != nil {
				t.Fatal(err)
			}
			if got != testCase.want {
				t.Fatalf("resolvePythonRuntime(%q) = %q, want %q", testCase.constraint, got, testCase.want)
			}
		})
	}
}

func TestResolvePythonRuntimeReportsCatalogDiagnostics(t *testing.T) {
	t.Parallel()
	_, err := resolvePythonRuntime("<3.10")
	var constraintErr *ecosystem.RuntimeConstraintError
	if !errors.As(err, &constraintErr) ||
		constraintErr.ReasonCode != ecosystem.RuntimeConstraintNoCompatible {
		t.Fatalf("resolvePythonRuntime() error = %T %v", err, err)
	}
	want := SupportedPythonRuntimeFamilies()
	slices.Reverse(want)
	if !reflect.DeepEqual(constraintErr.Supported, want) {
		t.Fatalf("diagnostic supported runtimes = %v, want catalog-derived order %v", constraintErr.Supported, want)
	}
}

func TestAllPythonAdaptersResolveEveryReviewedRuntime(t *testing.T) {
	t.Parallel()
	adapters := []ecosystem.Adapter{Poetry(), UV(), PipTools(), Requirements()}
	for _, adapter := range adapters {
		adapter := adapter
		for _, runtime := range SupportedPythonRuntimeFamilies() {
			runtime := runtime
			for _, platform := range []string{"linux/amd64", "linux/arm64"} {
				platform := platform
				t.Run(adapter.Key().PackageManager+"-"+runtime+"-"+platform, func(t *testing.T) {
					t.Parallel()
					spec, err := adapter.(ecosystem.ToolchainProvider).DefaultToolchain(ecosystem.Constraints{
						Key: adapter.Key(), Runtime: runtime + ".*", Platform: platform,
					})
					if err != nil {
						t.Fatal(err)
					}
					if spec.Runtime != runtime || spec.Platform != platform ||
						spec.BuildArgs["BASE_IMAGE"] != pythonBaseImage(runtime) {
						t.Fatalf("toolchain spec = %#v", spec)
					}
				})
			}
		}
	}
}

func TestAllPythonAdaptersUseDeclaredFallback(t *testing.T) {
	t.Parallel()
	_, fallback := PythonRuntimePolicy()
	for _, adapter := range []ecosystem.Adapter{Poetry(), UV(), PipTools(), Requirements()} {
		spec, err := adapter.(ecosystem.ToolchainProvider).DefaultToolchain(ecosystem.Constraints{
			Key: adapter.Key(), Platform: "linux/amd64",
		})
		if err != nil {
			t.Fatal(err)
		}
		if spec.Runtime != fallback {
			t.Fatalf("%s fallback = %q, want %q", adapter.Key().String(), spec.Runtime, fallback)
		}
	}
}
