package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestRepairCopiesBackOnlyAfterVerification(t *testing.T) {
	for _, scenario := range []string{"accept", "reject", "manifest_drift"} {
		reject := scenario != "accept"
		root := t.TempDir()
		manifest := filepath.Join(root, "package.json")
		lockfile := filepath.Join(root, "package-lock.json")
		const original = `{"dependencies":{"demo":"1.0.0"}}`
		for path, value := range map[string]string{manifest: original, lockfile: "{}"} {
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
		finding := vulnscan.Finding{ID: "CVE-test", Package: "demo", InstalledVersion: "1.0.0", FixedVersion: "1.0.1", Source: "trivy"}
		engine := Engine{
			Prepare: func(context.Context, config.Workspace, config.Config) (config.ToolchainProfile, error) {
				return config.ToolchainProfile{}, nil
			},
			Scan: func(_ context.Context, path string, _ config.Workspace, _ config.Config, _ bool) (vulnscan.Report, error) {
				data, err := os.ReadFile(filepath.Join(path, "package-lock.json"))
				if err != nil {
					return vulnscan.Report{}, err
				}
				if string(data) == "{}" || scenario == "reject" {
					return vulnscan.Report{Findings: []vulnscan.Finding{finding}}, nil
				}
				return vulnscan.Report{}, nil
			},
			Command: func(_ context.Context, _ config.ToolchainProfile, args []string, path string) (string, error) {
				file := filepath.Join(path, "package-lock.json")
				if args[0] == "npm" {
					// npm may rewrite the entire manifest while updating its lock.
					data, err := os.ReadFile(filepath.Join(path, "package.json"))
					if err != nil {
						return "", err
					}
					var formatted bytes.Buffer
					if err := json.Indent(&formatted, data, "", "  "); err != nil {
						return "", err
					}
					if scenario == "manifest_drift" {
						formatted.Reset()
						formatted.WriteString(`{"dependencies":{"demo":"1.0.1"},"unexpected":true}`)
					}
					if err := os.WriteFile(filepath.Join(path, "package.json"), formatted.Bytes(), 0600); err != nil {
						return "", err
					}
					return "", os.WriteFile(file, []byte(`{"fixed":true}`), 0600)
				}
				data, err := os.ReadFile(file)
				if err != nil {
					return "", err
				}
				if string(data) == "{}" {
					return `{"demo":{"direct":true,"versions":["1.0.0"]}}`, nil
				}
				return `{"demo":{"direct":true,"versions":["1.0.1"]}}`, nil
			},
		}
		result, err := engine.Run(context.Background(), config.Workspace{Path: root, Stack: "node", PackageManager: "npm"}, config.Config{}, Options{})
		if reject {
			data, readErr := os.ReadFile(manifest)
			if !errors.Is(err, ErrPartial) || readErr != nil || string(data) != original || len(result.ChangedFiles) != 0 {
				t.Fatalf("rejected candidate changed project: %+v, %v", result, err)
			}
		} else if err != nil || len(result.Fixed) != 1 || len(result.ChangedFiles) != 2 || !result.Complete {
			t.Fatalf("verified repair not applied: %+v, %v", result, err)
		} else {
			data, readErr := os.ReadFile(manifest)
			if readErr != nil || string(data) != strings.Replace(original, "1.0.0", "1.0.1", 1) {
				t.Fatalf("package manager formatting escaped: %q, %v", data, readErr)
			}
		}
	}
}

func TestBunRepairRewritesManifestAndLockOnlyAfterVerification(t *testing.T) {
	for _, reject := range []bool{false, true} {
		root := t.TempDir()
		const original = `{"dependencies":{"demo":"1.0.0"}}`
		for name, value := range map[string]string{"package.json": original, "bun.lock": "demo@1.0.0"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
		finding := vulnscan.Finding{ID: "CVE-test", Package: "demo", InstalledVersion: "1.0.0", FixedVersion: "1.0.1", Source: "trivy"}
		var commands [][]string
		engine := Engine{
			Prepare: func(context.Context, config.Workspace, config.Config) (config.ToolchainProfile, error) {
				return config.ToolchainProfile{}, nil
			},
			Scan: func(_ context.Context, path string, _ config.Workspace, _ config.Config, _ bool) (vulnscan.Report, error) {
				data, err := os.ReadFile(filepath.Join(path, "bun.lock"))
				if err != nil {
					return vulnscan.Report{}, err
				}
				if string(data) == "demo@1.0.0" || reject {
					return vulnscan.Report{Findings: []vulnscan.Finding{finding}}, nil
				}
				return vulnscan.Report{}, nil
			},
			Command: func(_ context.Context, _ config.ToolchainProfile, args []string, path string) (string, error) {
				commands = append(commands, args)
				file := filepath.Join(path, "bun.lock")
				if args[0] == "bun" && args[1] == "install" {
					return "", os.WriteFile(file, []byte("demo@1.0.1"), 0600)
				}
				data, err := os.ReadFile(file)
				if err != nil {
					return "", err
				}
				version := "1.0.0"
				if string(data) == "demo@1.0.1" {
					version = "1.0.1"
				}
				return `{"demo":{"direct":true,"versions":["` + version + `"]}}`, nil
			},
		}
		result, err := engine.Run(context.Background(), config.Workspace{Path: root, Stack: "node", PackageManager: "bun"}, config.Config{}, Options{})
		manifest, readErr := os.ReadFile(filepath.Join(root, "package.json"))
		lock, lockErr := os.ReadFile(filepath.Join(root, "bun.lock"))
		if readErr != nil || lockErr != nil {
			t.Fatal(readErr, lockErr)
		}
		if reject {
			if !errors.Is(err, ErrPartial) || string(manifest) != original || string(lock) != "demo@1.0.0" || len(result.ChangedFiles) != 0 {
				t.Fatalf("rejected Bun candidate changed project: %+v, %v", result, err)
			}
			continue
		}
		if err != nil || len(result.Fixed) != 1 || len(result.ChangedFiles) != 2 || !result.Complete || string(lock) != "demo@1.0.1" ||
			!strings.Contains(string(manifest), "1.0.1") {
			t.Fatalf("verified Bun repair not applied: %+v, %v, %s", result, err, manifest)
		}
		if len(commands) < 2 || !slices.Equal(commands[1], []string{"bun", "install", "--lockfile-only", "--ignore-scripts"}) {
			t.Fatalf("Bun repair did not use the scripts-disabled lock-only command: %v", commands)
		}
	}
}

func TestPlanChoosesSmallestCompatibleFix(t *testing.T) {
	findings := []vulnscan.Finding{
		{ID: "a", Package: "direct", InstalledVersion: "1.2.0", FixedVersion: "1.10.0, 2.0.0, 1.3.0", Severity: "HIGH"},
		{ID: "b", Package: "transitive", FixedVersion: "1.2.4", Severity: "HIGH"},
		{ID: "c", Package: "major", InstalledVersion: "1.2.0", FixedVersion: "2.0.0", Severity: "CRITICAL"},
		{ID: "d", Package: "unpatched", Severity: "HIGH"},
		{ID: "e", Package: "low", Severity: "LOW"},
	}
	metadata := map[string]ecosystem.FixDependency{
		"direct":     {Direct: true},
		"transitive": {Versions: []string{"1.2.3"}},
	}
	plan, err := Plan(findings, metadata, Options{MinSeverity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 5 || plan[0].TargetVersion != "1.3.0" || !plan[0].Dependency.Direct ||
		plan[1].TargetVersion != "1.2.4" || plan[1].Dependency.Direct ||
		plan[2].Reason != "needs_major" || plan[3].Reason != "no_fix" || plan[4].Reason != "filtered" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestRunSkipsDependabotUntilLocallyVerified(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package.json")
	const original = `{"dependencies":{"demo":"1.0.0"}}`
	if err := os.WriteFile(manifest, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	// Dependabot reports no installed version, so the fix cannot be confirmed locally.
	finding := vulnscan.Finding{ID: "GHSA-test", Package: "demo", FixedVersion: "1.0.1", Severity: "HIGH", Source: "github-dependabot"}
	engine := Engine{
		Scan: func(context.Context, string, config.Workspace, config.Config, bool) (vulnscan.Report, error) {
			return vulnscan.Report{Findings: []vulnscan.Finding{finding}}, nil
		},
		Prepare: func(context.Context, config.Workspace, config.Config) (config.ToolchainProfile, error) {
			t.Fatal("dependabot finding must not start package preparation")
			return config.ToolchainProfile{}, nil
		},
		Command: func(context.Context, config.ToolchainProfile, []string, string) (string, error) {
			t.Fatal("dependabot finding must not run package commands")
			return "", nil
		},
	}
	result, err := engine.Run(context.Background(), config.Workspace{Path: root, Stack: "node", PackageManager: "npm"}, config.Config{}, Options{})
	data, readErr := os.ReadFile(manifest)
	if err != nil || readErr != nil || string(data) != original || len(result.ChangedFiles) != 0 || len(result.Fixed) != 0 ||
		len(result.Skipped) != 1 || result.Skipped[0].Reason != "source_requires_local_verification" {
		t.Fatalf("dependabot finding was not skipped with its reason: %+v, %v", result, err)
	}
}
