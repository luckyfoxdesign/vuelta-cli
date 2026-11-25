package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func demoFinding(id, pkg, fixed string) vulnscan.Finding {
	return vulnscan.Finding{ID: id, Package: pkg, FixedVersion: fixed, Severity: "HIGH", Source: "trivy"}
}

// retryHarness simulates a direct dependency "demo" whose installed version is
// whatever the manifest declares once the lock-only install ran.
type retryHarness struct {
	root     string
	lockName string
	manager  string
	original map[string]string
	attempts []string
}

func newRetryHarness(t *testing.T, manager string) *retryHarness {
	t.Helper()
	h := &retryHarness{root: t.TempDir(), manager: manager, lockName: "package-lock.json"}
	if manager == "bun" {
		h.lockName = "bun.lock"
	}
	h.original = map[string]string{"package.json": `{"dependencies":{"demo":"1.0.0"}}`, h.lockName: "demo@1.0.0"}
	for name, value := range h.original {
		if err := os.WriteFile(filepath.Join(h.root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func lockVersion(t *testing.T, root, lockName string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, lockName))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(string(data), "demo@")
}

// engine reports the findings listed for the version recorded in the lockfile.
func (h *retryHarness) engine(t *testing.T, universe map[string][]vulnscan.Finding) Engine {
	return Engine{
		Prepare: func(context.Context, config.Workspace, config.Config) (config.ToolchainProfile, error) {
			return config.ToolchainProfile{}, nil
		},
		Scan: func(_ context.Context, path string, _ config.Workspace, _ config.Config, tracked bool) (vulnscan.Report, error) {
			version := lockVersion(t, path, h.lockName)
			if !tracked {
				h.attempts = append(h.attempts, version)
			}
			var findings []vulnscan.Finding
			for _, f := range universe[version] {
				f.InstalledVersion = version
				findings = append(findings, f)
			}
			return vulnscan.Report{Findings: findings}, nil
		},
		Command: func(_ context.Context, _ config.ToolchainProfile, args []string, path string) (string, error) {
			if len(args) > 1 && args[1] == "install" {
				data, err := os.ReadFile(filepath.Join(path, "package.json"))
				if err != nil {
					return "", err
				}
				var manifest struct {
					Dependencies map[string]string `json:"dependencies"`
				}
				if err = json.Unmarshal(data, &manifest); err != nil {
					return "", err
				}
				return "", os.WriteFile(filepath.Join(path, h.lockName), []byte("demo@"+manifest.Dependencies["demo"]), 0600)
			}
			return `{"demo":{"direct":true,"versions":["` + lockVersion(t, path, h.lockName) + `"]}}`, nil
		},
	}
}

func TestRetryTriesNextFixedVersionOfNewFinding(t *testing.T) {
	cases := []struct {
		name      string
		universe  map[string][]vulnscan.Finding
		wantFinal string // empty means every candidate is rejected
		attempts  []string
	}{
		{
			name: "second candidate is clean",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "1.0.2")},
			},
			wantFinal: "1.0.2",
			attempts:  []string{"1.0.1", "1.0.2"},
		},
		{
			name: "chain of several vulnerable candidates",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "1.0.2")},
				"1.0.2": {demoFinding("C", "demo", "1.0.3")},
				"1.0.3": {demoFinding("D", "demo", "1.0.4")},
			},
			wantFinal: "1.0.4",
			attempts:  []string{"1.0.1", "1.0.2", "1.0.3", "1.0.4"},
		},
		{
			name: "smallest fix inside the major wins",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "2.0.0, 1.0.5, 1.0.4")},
			},
			wantFinal: "1.0.4",
			attempts:  []string{"1.0.1", "1.0.4"},
		},
		{
			name: "next fix only in another major",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "2.0.0")},
			},
			attempts: []string{"1.0.1"},
		},
		{
			name: "new finding without a fix",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "")},
			},
			attempts: []string{"1.0.1"},
		},
		{
			name: "fix is not above the current target",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "1.0.1, 1.0.0")},
			},
			attempts: []string{"1.0.1"},
		},
		{
			name: "last reachable candidate is still vulnerable",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "1.0.2")},
				"1.0.2": {demoFinding("C", "demo", "")},
			},
			attempts: []string{"1.0.1", "1.0.2"},
		},
		{
			name: "new finding in another package does not retry",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "other", "1.0.2")},
			},
			attempts: []string{"1.0.1"},
		},
		{
			name: "mixed packages do not retry",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("B", "demo", "1.0.2"), demoFinding("C", "other", "9.0.0")},
				"1.0.2": {},
			},
			attempts: []string{"1.0.1"},
		},
		{
			name: "original finding that remains does not retry",
			universe: map[string][]vulnscan.Finding{
				"1.0.0": {demoFinding("A", "demo", "1.0.1")},
				"1.0.1": {demoFinding("A", "demo", "1.0.1"), demoFinding("B", "demo", "1.0.2")},
			},
			attempts: []string{"1.0.1"},
		},
	}
	for _, manager := range []string{"npm", "bun"} {
		for _, tc := range cases {
			t.Run(manager+"/"+tc.name, func(t *testing.T) {
				h := newRetryHarness(t, manager)
				ws := config.Workspace{Path: h.root, Stack: "node", PackageManager: manager}
				result, err := h.engine(t, tc.universe).Run(context.Background(), ws, config.Config{}, Options{})
				if !slices.Equal(h.attempts, tc.attempts) {
					t.Fatalf("attempted versions = %v, want %v", h.attempts, tc.attempts)
				}
				if tc.wantFinal == "" {
					if !errors.Is(err, ErrPartial) || len(result.ChangedFiles) != 0 || len(result.Fixed) != 0 {
						t.Fatalf("rejection must be partial and change nothing: %+v, %v", result, err)
					}
					for name, want := range h.original {
						got, readErr := os.ReadFile(filepath.Join(h.root, name))
						if readErr != nil || string(got) != want {
							t.Fatalf("%s changed after rejection: %q, %v", name, got, readErr)
						}
					}
					if len(result.Skipped) != 1 || result.Skipped[0].Reason != "candidate_rejected" ||
						result.Skipped[0].TargetVersion != tc.attempts[len(tc.attempts)-1] {
						t.Fatalf("skipped entry must name the last tried version: %+v", result.Skipped)
					}
					return
				}
				if err != nil || !result.Complete || len(result.Fixed) != 1 || len(result.Skipped) != 0 {
					t.Fatalf("repair not applied: %+v, %v", result, err)
				}
				if result.Fixed[0].TargetVersion != tc.wantFinal {
					t.Fatalf("target_version = %q, want written version %q", result.Fixed[0].TargetVersion, tc.wantFinal)
				}
				manifest, readErr := os.ReadFile(filepath.Join(h.root, "package.json"))
				if readErr != nil || !strings.Contains(string(manifest), `"`+tc.wantFinal+`"`) ||
					lockVersion(t, h.root, h.lockName) != tc.wantFinal {
					t.Fatalf("project does not hold %s: %s, %v", tc.wantFinal, manifest, readErr)
				}
			})
		}
	}
}

func TestResultJSONCarriesWrittenTargetVersion(t *testing.T) {
	data, err := json.Marshal(Result{
		Fixed:   []FixedFinding{{JSONFinding: vulnscan.JSONFinding{ID: "A", Package: "demo"}, TargetVersion: "1.0.2"}},
		Skipped: []Skipped{{Finding: vulnscan.JSONFinding{ID: "B", Package: "demo"}, Reason: "candidate_rejected", TargetVersion: "1.0.3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Fixed []struct {
			ID            string `json:"id"`
			TargetVersion string `json:"target_version"`
		} `json:"fixed"`
		Skipped []struct {
			TargetVersion string `json:"target_version"`
		} `json:"skipped"`
	}
	if err = json.Unmarshal(data, &decoded); err != nil || len(decoded.Fixed) != 1 || decoded.Fixed[0].ID != "A" ||
		decoded.Fixed[0].TargetVersion != "1.0.2" || len(decoded.Skipped) != 1 || decoded.Skipped[0].TargetVersion != "1.0.3" {
		t.Fatalf("unexpected JSON shape: %s, %v", data, err)
	}
}
