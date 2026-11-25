package remediation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestNPMTransitiveRepair(t *testing.T) {
	for _, tc := range []struct {
		name, reason                                                           string
		pinned, nested, commandFailure, scanFailure, manifestDrift, newFinding bool
	}{
		{name: "parent range permits target"},
		{name: "parent pin removes target", pinned: true, reason: "needs_parent_upgrade"},
		{name: "parent pin keeps vulnerable nested copy", pinned: true, nested: true, reason: "needs_parent_upgrade"},
		{name: "preparation fails", commandFailure: true, reason: "candidate_rejected"},
		{name: "rescan fails", scanFailure: true, reason: "candidate_rejected"},
		{name: "final install changes manifest", manifestDrift: true, reason: "candidate_rejected"},
		{name: "new unrelated finding", newFinding: true, reason: "candidate_rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			const original = "{\n  \"dependencies\": {\"parent\": \"1.0.0\"}\n}\n"
			originals := map[string]string{"package.json": original, "package-lock.json": "old"}
			for name, value := range originals {
				if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			finding := vulnscan.Finding{ID: "CVE-test", Package: "child", InstalledVersion: "1.0.0", FixedVersion: "1.0.1", Source: "trivy"}
			installs, rescans := 0, 0
			engine := Engine{
				Prepare: func(context.Context, config.Workspace, config.Config) (config.ToolchainProfile, error) {
					return config.ToolchainProfile{}, nil
				},
				Command: func(_ context.Context, _ config.ToolchainProfile, args []string, path string) (string, error) {
					lock := filepath.Join(path, "package-lock.json")
					if args[0] == "npm" && args[1] == "install" {
						installs++
						if path == root || !slices.Contains(args, "--ignore-scripts") || !slices.Contains(args, "--package-lock-only") {
							t.Fatalf("unsafe mutation: %v, %s", args, path)
						}
						// Real npm does not save a lockfile with --no-save.
						if slices.Contains(args, "--no-save") {
							return "", nil
						}
						if slices.Contains(args, "child@1.0.1") {
							if err := os.WriteFile(filepath.Join(path, "package.json"), []byte(`{"dependencies":{"parent":"1.0.0","child":"1.0.1"}}`), 0600); err != nil {
								return "", err
							}
							if tc.commandFailure {
								return "", errors.New("install failed")
							}
							return "", os.WriteFile(lock, []byte("target"), 0600)
						}
						manifest, err := os.ReadFile(filepath.Join(path, "package.json"))
						if err != nil || string(manifest) != original {
							t.Fatalf("manifest not restored before final install: %q, %v", manifest, err)
						}
						if tc.manifestDrift {
							return "", os.WriteFile(filepath.Join(path, "package.json"), []byte("{}"), 0600)
						}
						if tc.pinned && !tc.nested {
							return "", os.WriteFile(lock, []byte("old"), 0600)
						}
						return "", nil
					}
					data, err := os.ReadFile(lock)
					if err != nil {
						return "", err
					}
					versions := `"1.0.0"`
					if string(data) == "target" {
						versions = `"1.0.1"`
						if tc.nested {
							versions += `,"1.0.0"`
						}
					}
					return `{"child":{"direct":false,"versions":[` + versions + `]}}`, nil
				},
				Scan: func(_ context.Context, path string, _ config.Workspace, _ config.Config, tracked bool) (vulnscan.Report, error) {
					if !tracked {
						rescans++
						if tc.scanFailure {
							return vulnscan.Report{}, errors.New("scan failed")
						}
					}
					data, err := os.ReadFile(filepath.Join(path, "package-lock.json"))
					if err != nil {
						return vulnscan.Report{}, err
					}
					if string(data) == "old" || tc.pinned {
						return vulnscan.Report{Findings: []vulnscan.Finding{finding}}, nil
					}
					if tc.newFinding {
						return vulnscan.Report{Findings: []vulnscan.Finding{{ID: "CVE-new", Package: "other"}}}, nil
					}
					return vulnscan.Report{}, nil
				},
			}
			result, err := engine.Run(context.Background(), config.Workspace{Path: root, Stack: "node", PackageManager: "npm"}, config.Config{}, Options{})
			if tc.reason == "" {
				if err != nil || !result.Complete || len(result.Fixed) != 1 || result.Fixed[0].TargetVersion != "1.0.1" || len(result.Rescan) != 0 || !slices.Equal(result.ChangedFiles, []string{"package-lock.json"}) {
					t.Fatalf("repair failed: %+v, %v", result, err)
				}
				originals["package-lock.json"] = "target"
			} else {
				if len(result.Skipped) != 1 || result.Skipped[0].Reason != tc.reason || len(result.ChangedFiles) != 0 || len(result.Fixed) != 0 {
					t.Fatalf("wrong rejection: %+v, %v", result, err)
				}
				if (tc.reason == "candidate_rejected") != errors.Is(err, ErrPartial) {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			for name, want := range originals {
				got, readErr := os.ReadFile(filepath.Join(root, name))
				if readErr != nil || string(got) != want {
					t.Fatalf("unexpected %s: %q, %v", name, got, readErr)
				}
			}
			if !tc.commandFailure && installs != 2 {
				t.Fatalf("install count: %d", installs)
			}
			if strings.HasPrefix(tc.reason, "needs_parent") && rescans != 1 {
				t.Fatalf("parent refusal must be confirmed by rescan: %d", rescans)
			}
		})
	}
}
