//go:build realengine

package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/remediation"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
)

// TestRealEngineNPMTransitiveFix exercises real npm and Trivy behind the
// production egress policy. TMPDIR must be mounted at the same daemon path,
// as in scripts/real-engine-acceptance.sh.
func TestRealEngineNPMTransitiveFix(t *testing.T) {
	if os.Getenv("VUELTA_ACCEPTANCE_ROOT") == "" {
		t.Skip("manual/networked suite: requires shared TMPDIR and Docker socket")
	}
	dc := checkEngine(t, "").Developer
	dockerexec.ConfigureDefault(dockerexec.Endpoint{SocketPath: dc.Socket, Expected: dockerexec.DaemonIdentity{
		ID: dc.ExpectedDaemon.ID, ServerVersion: dc.ExpectedDaemon.ServerVersion,
		OperatingSystem: dc.ExpectedDaemon.OperatingSystem, Architecture: dc.ExpectedDaemon.Architecture,
		MinimumAPIVersion: dc.ExpectedDaemon.MinimumAPIVersion, RequiredSecurityOptions: dc.ExpectedDaemon.RequiredSecurityOptions,
	}})
	for _, tc := range []struct {
		parent, child, installed, target, id string
		pinned                               bool
	}{
		{"axios@0.21.0", "follow-redirects", "1.13.0", "1.14.7", "CVE-2022-0155", false},
		{"express@4.17.1", "qs", "6.7.0", "6.7.3", "CVE-2022-24999", true},
	} {
		t.Run(tc.child, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
			defer cancel()
			cfg := configinit.NewConfig()
			cfg.VulnScan.DependencySource = "trivy"
			session := egress.NewSession(cfg.Update.Egress, dockerexec.Default())
			ctx = egress.WithSession(ctx, session)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				if err := session.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			root, err := os.MkdirTemp(os.Getenv("VUELTA_ACCEPTANCE_ROOT"), "vuelta-acceptance-case-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			// Seed exact historical versions, then remove the temporary direct
			// child so the test starts with a genuinely transitive dependency.
			manifest := []byte("{\n  \"engines\": {\"node\": \"22.x\"},\n  \"packageManager\": \"npm@10.9.2\",\n  \"scripts\": {\"preinstall\": \"node -e \\\"process.exit(91)\\\"\"},\n  \"dependencies\": {}\n}\n")
			if err := os.WriteFile(filepath.Join(root, "package.json"), manifest, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
			ws := config.Workspace{Path: root, Stack: "node", PackageManager: "npm", Platform: "linux/" + dc.ExpectedDaemon.Architecture}
			prepared, err := toolchain.PrepareForFix(ctx, ws, *cfg, dockerexec.Default(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(root, 65532, 65532); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(filepath.Join(root, "package.json"), 65532, 65532); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(filepath.Join(root, "package-lock.json"), 65532, 65532); err != nil {
				t.Fatal(err)
			}
			run := updater.NewDockerRunnerForProfile(cfg.Update.Egress, "65532:65532", ws.Platform)
			if _, err := run(ctx, prepared.Profile.Image, []string{"npm", "install", "--package-lock-only", "--ignore-scripts", "--save-exact", tc.parent, tc.child + "@" + tc.installed}, root); err != nil {
				t.Fatal(err)
			}
			manifest, err = os.ReadFile(filepath.Join(root, "package.json"))
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(manifest, &doc); err != nil {
				t.Fatal(err)
			}
			delete(doc["dependencies"].(map[string]any), tc.child)
			manifest, err = json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			manifest = append(manifest, '\n')
			if err := os.WriteFile(filepath.Join(root, "package.json"), manifest, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := run(ctx, prepared.Profile.Image, []string{"npm", "install", "--package-lock-only", "--ignore-scripts"}, root); err != nil {
				t.Fatal(err)
			}
			lockBefore, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
			if err != nil {
				t.Fatal(err)
			}
			// Mutation ran as a separate non-root UID; Git now runs as the test
			// process. Restore ownership instead of disabling Git's safety check.
			for _, name := range []string{".", "package.json", "package-lock.json"} {
				if err := os.Chown(filepath.Join(root, name), os.Geteuid(), os.Getegid()); err != nil {
					t.Fatal(err)
				}
			}
			env := []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
			runTextInDir(t, ctx, env, root, "fixture", "git", "init", "--quiet")
			runTextInDir(t, ctx, env, root, "fixture", "git", "add", "package.json", "package-lock.json")
			result, err := (remediation.Engine{}).Run(ctx, ws, *cfg, remediation.Options{FindingIDs: []string{tc.id}, Diagnostic: func(err error) { t.Log(err) }})
			if err != nil {
				t.Fatalf("repair failed: %+v: %v", result, err)
			}
			after, err := os.ReadFile(filepath.Join(root, "package.json"))
			if err != nil || !bytes.Equal(after, manifest) {
				t.Fatalf("manifest changed: %v", err)
			}
			if !result.Complete {
				t.Fatal("incomplete rescan")
			}
			if tc.pinned {
				found := false
				for _, item := range result.Skipped {
					if item.Finding.ID == tc.id && item.Reason == "needs_parent_upgrade" {
						found = true
					}
				}
				if !found || len(result.ChangedFiles) != 0 {
					t.Fatalf("parent pin not reported: %+v", result)
				}
				lockAfter, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
				if err != nil || !bytes.Equal(lockAfter, lockBefore) {
					t.Fatalf("rejected lock changed: %v", err)
				}
			} else {
				if len(result.Fixed) != 1 || result.Fixed[0].ID != tc.id || result.Fixed[0].TargetVersion != tc.target || !slices.Equal(result.ChangedFiles, []string{"package-lock.json"}) {
					t.Fatalf("unexpected repair: %+v", result)
				}
				for _, finding := range result.Rescan {
					if finding.ID == tc.id {
						t.Fatal("original finding remains")
					}
				}
			}
			t.Logf("%s: target=%s changed=%v", tc.child, tc.target, result.ChangedFiles)
		})
	}
}
