package vulnscan

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestFindingsJSONGolden(t *testing.T) {
	trivy, _, _, err := parseTrivy([]byte(`{"Results":[{"Target":"pnpm-lock.yaml","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"example","InstalledVersion":"1.0.0","FixedVersion":" 2.0.0, 1.0.1 ","Severity":"HIGH"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	osv, _, err := parseOSV([]byte(`{"database_updated_at":"2026-11-24T00:00:00Z","results":[{"source":{"path":"uv.lock"},"packages":[{"package":{"name":"demo","version":"1.0","ecosystem":"PyPI"},"vulnerabilities":[{"id":"GHSA-1","aliases":["CVE-2"],"database_specific":{"severity":"MODERATE"},"affected":[{"package":{"name":"other","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"999"}]}]},{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"1.1"}]}]}]}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	image := Finding{ID: "CVE-3", Kind: "image", Package: "openssl", InstalledVersion: "3.0", Severity: "unrecognized", Target: "alpine", Source: "trivy", Image: "alpine:3.20"}
	findings := append(trivy, osv...)
	findings = append(findings, image)
	got, err := json.MarshalIndent(StructuredFindings(findings), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/findings.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got)+"\n" != string(want) {
		t.Fatalf("findings JSON mismatch:\n%s", got)
	}
	findings[0], findings[2] = findings[2], findings[0]
	if !reflect.DeepEqual(StructuredFindings(findings), StructuredFindings(append(append(trivy, osv...), image))) {
		t.Fatal("order depends on source order")
	}
}

func TestSeverityVocabulary(t *testing.T) {
	for value, want := range map[string]string{"CRITICAL": "critical", "high": "high", " Moderate ": "medium", "MEDIUM": "medium", "LOW": "low", "": "unknown", "info": "unknown"} {
		if got := NormalizeSeverity(value); got != want {
			t.Fatalf("%q: got %q, want %q", value, got, want)
		}
	}
}

func TestDockerHubTransportUsesAllowlistedRegistry(t *testing.T) {
	for reference, want := range map[string]string{
		"alpine:3.10.0":                   "registry-1.docker.io/library/alpine:3.10.0",
		"docker.io/alpine:3.10.0":         "registry-1.docker.io/library/alpine:3.10.0",
		"docker.io/library/alpine:3.10.0": "registry-1.docker.io/library/alpine:3.10.0",
		"index.docker.io/acme/app:1":      "registry-1.docker.io/acme/app:1",
		"acme/app:1":                      "registry-1.docker.io/acme/app:1",
		"ghcr.io/acme/app:1":              "ghcr.io/acme/app:1",
		"localhost:5000/app:1":            "localhost:5000/app:1",
	} {
		if got := trivyRegistryReference(reference); got != want {
			t.Fatalf("%s: got %s, want %s", reference, got, want)
		}
	}
}
