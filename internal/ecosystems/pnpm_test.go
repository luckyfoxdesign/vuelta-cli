package ecosystems

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestPNPMDecoderSupportedVersionMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		major                  int
		version, lock, current string
	}{
		{8, "8.15.9", "6.0", "1.0.0"},
		{9, "9.15.0", "9.0", "1.0.0"},
		{10, "10.14.0", "9.0", ""},
		{11, "11.4.0", "9.0", "1.0.0"},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(fmt.Sprintf("pnpm-%d", testCase.major), func(t *testing.T) {
			t.Parallel()
			inputs := pnpmInputs(testCase.version, testCase.lock)
			output, err := os.ReadFile(filepath.Join("testdata", "pnpm", fmt.Sprintf("v%d.json", testCase.major)))
			if err != nil {
				t.Fatal(err)
			}
			report, err := PNPM().(ecosystem.CandidateDecoder).DecodeCandidates(output, inputs)
			if err != nil || len(report.Candidates) != 1 ||
				report.Candidates[0].Current != testCase.current ||
				report.Candidates[0].Target != "2.0.0" {
				t.Fatalf("DecodeCandidates() = %#v, %v", report, err)
			}
		})
	}
}

func TestPNPMDecoderSeparatesOutputFailureKinds(t *testing.T) {
	t.Parallel()
	inputs := pnpmInputs("10.14.0", "9.0")
	tests := []struct {
		name   string
		output string
		kind   ecosystem.CandidateFailureKind
	}{
		{"stderr-style notice on stdout", "ERR_PNPM_FETCH_500 registry failed\n{}", ecosystem.CandidateFailureNonJSON},
		{"truncated json", `{"demo":{"latest":"2.0.0"}`, ecosystem.CandidateFailureTruncatedJSON},
		{"unexpected field", `{"demo":{"latest":"2.0.0","registryToken":"must-not-pass"}}`, ecosystem.CandidateFailureSchemaMismatch},
		{"wrong root", `[{"name":"demo","latest":"2.0.0"}]`, ecosystem.CandidateFailureSchemaMismatch},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := PNPM().(ecosystem.CandidateDecoder).DecodeCandidates([]byte(testCase.output), inputs)
			var candidateErr *ecosystem.CandidateError
			if !errors.As(err, &candidateErr) || candidateErr.Kind != testCase.kind {
				t.Fatalf("error = %#v, want kind %q", err, testCase.kind)
			}
		})
	}
}

func TestPNPMVersionPolicyNormalizesCorepackIntegrity(t *testing.T) {
	t.Parallel()
	got, family, err := approvedPNPMVersion(
		"10.14.0+sha512.AbCdEf0123+/=", "pnpm-v9",
	)
	if err != nil || got != "10.14.0" || family != 10 {
		t.Fatalf("approvedPNPMVersion() = %q, %d, %v", got, family, err)
	}
	if _, _, err := approvedPNPMVersion("12.0.0", "pnpm-v9"); err == nil {
		t.Fatal("unsupported pnpm family was accepted")
	}
	if _, _, err := approvedPNPMVersion("8.15.9", "pnpm-v9"); err == nil {
		t.Fatal("pnpm 8 with a v9 lockfile was accepted")
	}
}

func TestPNPMCandidateScannerHasBoundedWorkingMemory(t *testing.T) {
	t.Parallel()
	spec, err := PNPM().(ecosystem.ScannerProvider).Scanner(ecosystem.ScannerRequest{
		ProfileScanner: "pnpm", ScannerVersion: "11.8.0", InstalledTool: true,
		MinReleaseAgeDays: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Memory != "2g" {
		t.Fatalf("pnpm scanner memory = %q, want 2g", spec.Memory)
	}
}

func pnpmInputs(version, lockVersion string) map[string][]byte {
	return map[string][]byte{
		"package.json":   []byte(fmt.Sprintf(`{"packageManager":"pnpm@%s"}`, version)),
		"pnpm-lock.yaml": []byte(fmt.Sprintf("lockfileVersion: '%s'\n", lockVersion)),
	}
}
