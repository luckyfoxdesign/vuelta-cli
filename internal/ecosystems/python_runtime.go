package ecosystems

import "github.com/luckyfoxdesign/vuelta/internal/ecosystem"

// PythonRuntimeRelease is one reviewed CPython minor family in Vuelta's
// embedded runtime policy. Lifecycle data is review context only: production
// resolution never expands the catalog from network or project input.
type PythonRuntimeRelease struct {
	Family      string
	Lifecycle   string
	UpstreamEOL string
}

var embeddedPythonRuntimePolicy = struct {
	Fallback string
	Releases []PythonRuntimeRelease
}{
	Fallback: "3.12",
	Releases: []PythonRuntimeRelease{
		{Family: "3.10", Lifecycle: "security", UpstreamEOL: "2026-10"},
		{Family: "3.11", Lifecycle: "security", UpstreamEOL: "2027-10"},
		{Family: "3.12", Lifecycle: "security", UpstreamEOL: "2028-10"},
		{Family: "3.13", Lifecycle: "bugfix", UpstreamEOL: "2029-10"},
		{Family: "3.14", Lifecycle: "bugfix", UpstreamEOL: "2030-10"},
	},
}

// PythonRuntimePolicy returns a defensive copy of the reviewed embedded
// policy. Callers cannot mutate the production catalog.
func PythonRuntimePolicy() ([]PythonRuntimeRelease, string) {
	releases := append([]PythonRuntimeRelease(nil), embeddedPythonRuntimePolicy.Releases...)
	return releases, embeddedPythonRuntimePolicy.Fallback
}

// SupportedPythonRuntimeFamilies returns the ordered reviewed minor families.
func SupportedPythonRuntimeFamilies() []string {
	releases, _ := PythonRuntimePolicy()
	families := make([]string, 0, len(releases))
	for _, release := range releases {
		families = append(families, release.Family)
	}
	return families
}

func resolvePythonRuntime(constraint string) (string, error) {
	return ecosystem.ResolveRuntime(
		"python",
		constraint,
		embeddedPythonRuntimePolicy.Fallback,
		SupportedPythonRuntimeFamilies(),
	)
}

func pythonBaseImage(runtime string) string {
	return "python:" + runtime + "-slim-bookworm"
}
