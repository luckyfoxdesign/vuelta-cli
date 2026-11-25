package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestRewriteJSONPreservesFormatting(t *testing.T) {
	for _, original := range []string{
		`{"name":"demo","dependencies":{"demo":"1.0.0"},"description":"1.0.0"}`,
		"{\n\t\"devDependencies\": { \"demo\": \"1.0.0\" },\n\t\"name\": \"example\"\n}\n",
		"{\r\n  \"optionalDependencies\": {\"demo\":\"1.0.0\"},\r\n  \"peerDependencies\": {\"demo\":\"1.0.0\"}\r\n}\r\n",
		`{"dependencies":{"de\u006do":"1.0.0","other":"1.0.0"},"nested":{"dependencies":{"demo":"1.0.0"}}}`,
	} {
		t.Run(original, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "package.json")
			if err := os.WriteFile(path, []byte(original), 0640); err != nil {
				t.Fatal(err)
			}
			if err := rewriteJSON(root, "package.json", "demo", "1.0.1", func(err error) { t.Fatalf("unexpected fallback: %v", err) }); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.ReplaceAll(original, `"demo":"1.0.0"`, `"demo":"1.0.1"`)
			want = strings.ReplaceAll(want, `"demo": "1.0.0"`, `"demo": "1.0.1"`)
			if strings.Contains(original, `de\u006do`) {
				want = strings.Replace(original, `de\u006do":"1.0.0`, `de\u006do":"1.0.1`, 1)
			}
			if string(got) != want {
				t.Fatalf("format changed: got %q want %q", got, want)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0640 {
				t.Fatalf("mode changed: %v", err)
			}
		})
	}
}

func TestRewriteJSONFallbackAndInvalidInput(t *testing.T) {
	for _, original := range []string{`{"dependencies":{"demo":"1.0.0","demo":"1.0.0"}}`, `{"dependencies":`} {
		root := t.TempDir()
		path := filepath.Join(root, "package.json")
		if err := os.WriteFile(path, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
		var diagnostics []string
		err := rewriteJSON(root, "package.json", "demo", "1.0.1", func(err error) { diagnostics = append(diagnostics, err.Error()) })
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if json.Valid([]byte(original)) {
			if err != nil || len(diagnostics) != 1 || !strings.Contains(diagnostics[0], "formatting_fallback") || !json.Valid(got) {
				t.Fatalf("fallback failed: %q %v %v", got, diagnostics, err)
			}
		} else if err == nil || string(got) != original {
			t.Fatalf("invalid input was written: %q %v", got, err)
		}
	}
}

func TestImageCandidateDiagnostics(t *testing.T) {
	for _, scenario := range []string{"finding_remains", "scan_incomplete", "digest_unavailable", "digest_mismatch", "verification_incomplete", "verification_finding_remains", "accepted"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			image := "alpine:3.19.0"
			if strings.HasPrefix(scenario, "digest_") {
				image += "@sha256:" + strings.Repeat("a", 64)
			}
			original := "FROM " + image + "\n"
			if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			a := vulnscan.Finding{Kind: "image", Image: image, ID: "CVE-a", Package: "a"}
			b := vulnscan.Finding{Kind: "image", Image: image, ID: "CVE-b", Package: "b"}
			engine := Engine{Scan: func(_ context.Context, path string, ws config.Workspace, _ config.Config, _ bool) (vulnscan.Report, error) {
				if path == root {
					return vulnscan.Report{Findings: []vulnscan.Finding{a, b}}, nil
				}
				report := vulnscan.Report{ImageResolutions: []vulnscan.ImageResolution{{ResolvedDigest: "sha256:" + strings.Repeat("b", 64)}}}
				switch scenario {
				case "finding_remains":
					report.Findings = []vulnscan.Finding{a, a} // one selected finding, even if repeated per platform
				case "scan_incomplete":
					return report, errors.New("PRIVATE scanner output must never escape")
				case "digest_unavailable":
					report.ImageResolutions[0].ResolvedDigest = "invalid"
				case "digest_mismatch":
					report.ImageResolutions = append(report.ImageResolutions, vulnscan.ImageResolution{ResolvedDigest: "sha256:" + strings.Repeat("c", 64)})
				case "verification_incomplete":
					if len(ws.DockerImages.RuntimeImages) == 0 {
						return report, errors.New("PRIVATE verification output")
					}
				case "verification_finding_remains":
					if len(ws.DockerImages.RuntimeImages) == 0 {
						report.Findings = []vulnscan.Finding{b}
					}
				}
				return report, nil
			}}
			var diagnostics []string
			result, err := engine.Run(context.Background(), config.Workspace{Path: root, Stack: config.StackDocker, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}}}, config.Config{}, Options{Diagnostic: func(err error) { diagnostics = append(diagnostics, err.Error()) }})
			if err != nil || len(result.ImageRepairs) != 1 {
				t.Fatalf("result: %+v %v", result, err)
			}
			detail := result.ImageRepairs[0]
			wantCount := 17
			if scenario == "accepted" {
				wantCount = 1
			}
			if len(detail.Candidates) != wantCount || detail.Selected != 2 {
				t.Fatalf("detail: %+v", detail)
			}
			for _, c := range detail.Candidates {
				if c.Reason != scenario {
					t.Fatalf("candidate: %+v", c)
				}
			}
			if scenario == "finding_remains" && (detail.BestRemaining == nil || *detail.BestRemaining != 1 || !strings.Contains(detail.Summary(), "1/2")) {
				t.Fatalf("best: %+v", detail)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded)+strings.Join(diagnostics, ""), "PRIVATE") || !strings.Contains(string(encoded), `"candidates"`) || len(diagnostics) < wantCount {
				t.Fatalf("unsafe/missing diagnostics: %s %v", encoded, diagnostics)
			}
			got, readErr := os.ReadFile(filepath.Join(root, "Dockerfile"))
			if readErr != nil || scenario != "accepted" && string(got) != original {
				t.Fatalf("rejected image changed: %q %v", got, readErr)
			}
		})
	}
}

func TestImageFindingSelectionAllowsPartialGroupRepair(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM alpine:3.19.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := vulnscan.Finding{Kind: "image", Image: "alpine:3.19.0", ID: "CVE-a", Package: "a"}
	b := vulnscan.Finding{Kind: "image", Image: "alpine:3.19.0", ID: "CVE-b", Package: "b"}
	calls := 0
	engine := Engine{Scan: func(context.Context, string, config.Workspace, config.Config, bool) (vulnscan.Report, error) {
		calls++
		r := vulnscan.Report{Findings: []vulnscan.Finding{a}, ImageResolutions: []vulnscan.ImageResolution{{}}}
		if calls == 1 {
			r.Findings = append(r.Findings, b)
		}
		return r, nil
	}}
	result, err := engine.Run(context.Background(), config.Workspace{Path: root, Stack: config.StackDocker, DockerImages: &config.DockerImagesSpec{Files: []string{"Dockerfile"}}}, config.Config{}, Options{FindingIDs: []string{"CVE-b"}})
	if err != nil || len(result.Fixed) != 1 || result.Fixed[0].ID != "CVE-b" || result.ImageRepairs[0].Selected != 1 || result.ImageRepairs[0].Reason != "accepted" {
		t.Fatalf("selection failed: %+v %v", result, err)
	}
}
