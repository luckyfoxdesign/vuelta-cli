package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func TestReadOnlyScanLeavesProjectUnchanged(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[reuse], func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "machine"))
			writeScanProjectFile(t, root, "package.json", "{}\n")
			if reuse {
				if _, _, err := selectScanConfiguration(scanOptions{directory: root}, "unused"); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			options, _, err := parseScanOptions([]string{"--directory", root, "--read-only", "--json"})
			if err != nil {
				t.Fatal(err)
			}
			if options.only != "vulnerabilities" || !options.nonInteractive {
				t.Fatal("read-only mode is not noninteractive vulnerability-only")
			}
			cfg, selection, err := selectReadOnlyScanConfiguration(options, "unused")
			if err != nil {
				t.Fatal(err)
			}
			if selection.OnboardingChanged {
				t.Fatal("onboarding ran")
			}
			workspace := cfg.Workspaces[0]
			runners := scanStageRunners{
				vulnerabilities: func(context.Context, config.Config, scanTarget, scanOptions) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
					return []vulnscan.Finding{{ID: "CVE-1", Package: "example", Severity: "HIGH", Source: "trivy"}}, nil, nil, "trivy", true, nil
				},
				alerts: func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error) {
					return nil, false, nil
				},
			}
			result := scanOneTargetWith(context.Background(), *cfg, scanTarget{path: root, workspace: &workspace}, options, runners)
			results := writeProjectScanReports([]scanResult{result}, options, time.Now())
			if len(results[0].VulnerabilityFindings) != 1 {
				t.Fatalf("findings lost: %+v", results)
			}
			after, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("project changed: %v -> %v", before, after)
			}
			if _, err := os.Stat(filepath.Join(root, ".vuelta")); !os.IsNotExist(err) {
				t.Fatalf("private state created: %v", err)
			}
		})
	}
}

func TestScanJSONContractIncludesEmptyFindingsAndVersion(t *testing.T) {
	stdout, _ := captureScanOutput(t, func() {
		if err := writeScanJSONEnvelope(jsonCommandEnvelope{Command: "scan", Results: []scanResult{{Status: "failed"}}}); err != nil {
			t.Fatal(err)
		}
	})
	var decoded struct {
		SchemaVersion int `json:"schema_version"`
		Results       []struct {
			Findings []json.RawMessage `json:"findings"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"vulnerabilities", "candidates", "snapshot_id", "package_updates", "verification"} {
		if _, exists := raw.Results[0][retired]; exists {
			t.Fatalf("retired field %s was emitted", retired)
		}
	}
	if decoded.SchemaVersion != 1 || len(decoded.Results) != 1 || decoded.Results[0].Findings == nil {
		t.Fatalf("invalid envelope: %s", stdout)
	}
}

func TestReadOnlyDetectsDockerWithoutOnboarding(t *testing.T) {
	for _, packages := range []bool{false, true} {
		root := t.TempDir()
		writeScanProjectFile(t, root, "Dockerfile", "FROM alpine:3.10.0\n")
		stack := "docker"
		if packages {
			writeScanProjectFile(t, root, "package.json", "{}\n")
			stack = "node"
		}
		targets := prepareReadOnlyTargets([]scanTarget{{path: root}}, stack)
		if targets[0].err != nil {
			t.Fatal(targets[0].err)
		}
		if targets[0].workspace == nil || targets[0].workspace.DockerImages == nil || len(targets[0].workspace.DockerImages.Files) != 1 {
			t.Fatalf("missing Docker inputs: %+v", targets[0])
		}
		if _, err := os.Stat(filepath.Join(root, projectConfigName)); !os.IsNotExist(err) {
			t.Fatalf("configuration written: %v", err)
		}
	}
}

func TestStructuredFindingsRetainAllAffectedLocations(t *testing.T) {
	findings := []vulnscan.Finding{
		{ID: "CVE-1", Package: "a", Target: "lock", Source: "trivy"},
		{ID: "CVE-1", Package: "b", Target: "lock", Source: "trivy"},
		{ID: "CVE-1", Package: "a", Target: "alpine", Source: "trivy", Kind: "image", Image: "alpine:3.24"},
		{ID: "CVE-1", Package: "a", Target: "alpine", Source: "trivy", Kind: "image", Image: "alpine:3.25"},
	}
	got := appendUniqueFindings(nil, append(findings, findings[0])...)
	if len(got) != 4 {
		t.Fatalf("affected locations collapsed: %+v", got)
	}
	if refs := findingRefs(got); len(refs) != 1 || refs[0] != "CVE-1" {
		t.Fatalf("legacy references changed: %v", refs)
	}
}

func TestRepairTargetsAdmitBunButReadOnlyScanDoesNot(t *testing.T) {
	root := t.TempDir()
	writeScanProjectFile(t, root, "package.json", `{"packageManager":"bun@1.4.5"}`+"\n")
	writeScanProjectFile(t, root, "bun.lock", "{}\n")
	repair := prepareTargets([]scanTarget{{path: root}}, "node", true)
	if repair[0].err != nil || repair[0].workspace == nil || repair[0].workspace.PackageManager != "bun" {
		t.Fatalf("fix must admit Bun: %+v", repair[0])
	}
	scan := prepareReadOnlyTargets([]scanTarget{{path: root}}, "node")
	if scan[0].err == nil || !strings.Contains(scan[0].err.Error(), "candidate-scanner") {
		t.Fatalf("scan must keep rejecting Bun: %+v", scan[0])
	}
	if _, err := os.Stat(filepath.Join(root, projectConfigName)); !os.IsNotExist(err) {
		t.Fatalf("configuration written: %v", err)
	}
}
