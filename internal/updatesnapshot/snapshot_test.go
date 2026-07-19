package updatesnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
)

func testSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snapshot, err := New(time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC), time.Hour, WorkspaceIdentity{
		CanonicalPath: "/projects/example", BaseRevision: "abc123", Input: InputIdentity{
			Stages: []string{"package-candidates"}, ManifestHash: strings.Repeat("c", 64), Hashes: map[string]string{"package.json": strings.Repeat("b", 64)},
		},
	}, strings.Repeat("a", 64), strings.Repeat("d", 64), []Candidate{{Kind: "npm", Name: "example", Target: "1.2.3"}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshots")
	store := Store{Dir: dir}
	want := testSnapshot(t)
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.PolicyHash != want.PolicyHash || len(got.Candidates) != 1 {
		t.Fatalf("loaded snapshot = %#v", got)
	}
	info, err := os.Stat(filepath.Join(dir, want.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestFormatSixRecordsRequiredSecurityAndVerificationIdentity(t *testing.T) {
	snapshot := testSnapshot(t)
	if snapshot.Format != 6 || snapshot.Origin != OriginWorkspace || snapshot.Project != "example" || snapshot.VerificationHash == "" {
		t.Fatalf("snapshot identity = %#v", snapshot)
	}
	if snapshot.Policy.Path != PolicyNone || snapshot.Policy.Hash != PolicyNone || snapshot.Gates.MinReleaseAge == "" {
		t.Fatalf("snapshot policy identity = %#v, gates = %#v", snapshot.Policy, snapshot.Gates)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"release_age_verified":false`) {
		t.Fatalf("candidate verification marker missing from %s", data)
	}
}

func TestSnapshotRecordsAdaptiveToolchainSourceImageIDAndVersions(t *testing.T) {
	snapshot := testSnapshot(t)
	imageID := "sha256:" + strings.Repeat("a", 64)
	profile := config.ToolchainProfile{
		Version: config.ToolchainProfileVersion, ID: "default-node24-npm", Stack: config.StackNode,
		PackageManager: "npm", Runtime: "24", PackageManagerVersion: "11.4.2",
		Scanner: "ncu", ScannerVersion: "22.2.9", Image: imageID, Platform: "linux/arm64", User: "10001:10001",
		LockFormats: []string{"npm-v2", "npm-v3"}, Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: true, ReleaseAge: true},
	}
	identity, err := toolchain.IdentityForResolvedProfile(profile, toolchain.SourceDefault, imageID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Toolchain = identity
	if err := validateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Toolchain.Source != "default" || snapshot.Toolchain.ImageID != imageID || snapshot.Toolchain.Runtime != "24" || snapshot.Toolchain.PackageManagerVersion != "11.4.2" || snapshot.Toolchain.ScannerVersion != "22.2.9" {
		t.Fatalf("toolchain snapshot identity = %#v", snapshot.Toolchain)
	}
}

func TestStoreRejectsOlderFormatsWithRerunHint(t *testing.T) {
	for _, format := range []int{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprintf("format-%d", format), func(t *testing.T) {
			store := Store{Dir: filepath.Join(t.TempDir(), "snapshots")}
			if err := ensureDir(store.Dir); err != nil {
				t.Fatal(err)
			}
			id := "abcdefghijklmnopqrstuv"
			data := []byte(fmt.Sprintf(`{"format":%d,"id":%q}`, format, id))
			if err := os.WriteFile(filepath.Join(store.Dir, id+".json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := store.Load(id)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "rerun vuelta scan") {
				t.Fatalf("format-%d error = %v", format, err)
			}
		})
	}
}

func TestAdhocSnapshotBindsInputsPolicyAndGates(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.yaml")
	policyData := []byte("allowed_packages:\n  - example\n")
	if err := os.WriteFile(policyPath, policyData, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(policyData)
	inputs := InputIdentity{
		Stages: []string{"package-candidates"}, ManifestHash: strings.Repeat("b", 64),
		Hashes: map[string]string{"package.json": strings.Repeat("c", 64), "package-lock.json": strings.Repeat("d", 64)},
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	policy := PolicyIdentity{Path: policyPath, Hash: fmt.Sprintf("%x", sum)}
	gates := ScanGates{AllowProjectConfig: true, MinReleaseAge: "168h0m0s"}
	effectiveHash, err := EffectivePolicyHash("adhoc", policy, gates)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewAdhoc(now, time.Hour, root, inputs, policy, gates, effectiveHash, []Candidate{{Kind: "npm", Name: "example", Target: "2.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateForAdhoc(snapshot, root, inputs, now); err != nil {
		t.Fatalf("validate adhoc snapshot: %v", err)
	}
	changedInputs := cloneInputIdentity(inputs)
	changedInputs.Hashes["package.json"] = strings.Repeat("e", 64)
	if err := ValidateForAdhoc(snapshot, root, changedInputs, now); !errors.Is(err, ErrStale) {
		t.Fatalf("changed-input error = %v", err)
	}
	if err := ValidateForAdhoc(snapshot, filepath.Join(root, "other"), inputs, now); !errors.Is(err, ErrStale) {
		t.Fatalf("changed-target error = %v", err)
	}
	tampered := snapshot
	tampered.PolicyHash = strings.Repeat("f", 64)
	if err := ValidateForAdhoc(tampered, root, inputs, now); !errors.Is(err, ErrStale) {
		t.Fatalf("changed-effective-policy error = %v", err)
	}
	if err := os.WriteFile(policyPath, append(policyData, []byte("# changed\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateForAdhoc(snapshot, root, inputs, now); !errors.Is(err, ErrStale) {
		t.Fatalf("changed-policy error = %v", err)
	}
}

func TestStoreRejectsMalformedScanGate(t *testing.T) {
	snapshot := testSnapshot(t)
	snapshot.Gates.MinReleaseAge = "forever"
	if err := (Store{Dir: filepath.Join(t.TempDir(), "snapshots")}).Save(snapshot); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Save error = %v, want invalid gate", err)
	}
}

func TestLoadMissingSnapshotDoesNotCreateStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	_, err := (Store{Dir: dir}).Load("abcdefghijklmnopqrstuv")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load error = %v, want not found", err)
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state directory was created during validation: %v", statErr)
	}
}

func TestValidateCandidatesFailsClosedOneGatePerCase(t *testing.T) {
	base := testSnapshot(t)
	base.Candidates[0].ReleaseAgeVerified = true
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"unsupported kind", func(snapshot *Snapshot) { snapshot.Candidates[0].Kind = "shell" }},
		{"flag injection", func(snapshot *Snapshot) { snapshot.Candidates[0].Name = "--registry" }},
		{"duplicate", func(snapshot *Snapshot) { snapshot.Candidates = append(snapshot.Candidates, snapshot.Candidates[0]) }},
		{"unverified age", func(snapshot *Snapshot) { snapshot.Candidates[0].ReleaseAgeVerified = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base
			snapshot.Candidates = append([]Candidate(nil), base.Candidates...)
			test.mutate(&snapshot)
			if err := ValidateCandidates(snapshot, false); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ValidateCandidates error = %v, want invalid", err)
			}
		})
	}
	base.Candidates[0].ReleaseAgeVerified = false
	if err := ValidateCandidates(base, true); err != nil {
		t.Fatalf("explicit unverified-age authorization rejected: %v", err)
	}
}

func TestStoreRejectsTraversalAndTampering(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "snapshots")}
	if _, err := store.Load("../../outside"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("traversal error = %v, want invalid", err)
	}
	snapshot := testSnapshot(t)
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, snapshot.ID+".json"), []byte(`{"format":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(snapshot.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered load error = %v, want invalid", err)
	}
}

func TestStoreRejectsCandidateFileTraversal(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "snapshots")}
	snapshot := testSnapshot(t)
	snapshot.Candidates[0].File = "../../outside"
	if err := store.Save(snapshot); !errors.Is(err, ErrInvalid) {
		t.Fatalf("save traversal candidate error = %v, want invalid", err)
	}
}

func TestValidateForWorkspaceRejectsExpiredBeforeReadingWorkspace(t *testing.T) {
	snapshot := testSnapshot(t)
	err := ValidateForWorkspace(context.Background(), snapshot, config.Config{}, config.Workspace{}, snapshot.ExpiresAt)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("validation error = %v, want expired", err)
	}
}
