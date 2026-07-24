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

func testSnapshotForRoot(t *testing.T, root string, now time.Time, ttl time.Duration) Snapshot {
	t.Helper()
	snapshot, err := New(now, ttl, WorkspaceIdentity{
		CanonicalPath: root, BaseRevision: "abc123", Input: InputIdentity{
			Stages: []string{"package-candidates"}, ManifestHash: strings.Repeat("c", 64),
			Hashes: map[string]string{"package.json": strings.Repeat("b", 64)},
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

func TestFormatSevenRecordsTargetSecurityAndVerificationIdentity(t *testing.T) {
	snapshot := testSnapshot(t)
	if snapshot.Format != 7 || snapshot.TargetRoot != "/projects/example" || snapshot.Origin != OriginWorkspace || snapshot.Project != "example" || snapshot.VerificationHash == "" {
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

func TestProjectStoreSelectsNewestDeterministicallyAndDoesNotFallbackFromExpired(t *testing.T) {
	root := t.TempDir()
	store, err := ProjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	older := testSnapshotForRoot(t, root, base, 24*time.Hour)
	newerExpired := testSnapshotForRoot(t, root, base.Add(time.Hour), time.Minute)
	for _, snapshot := range []Snapshot{older, newerExpired} {
		if err := store.Save(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	selected, err := store.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != newerExpired.ID {
		t.Fatalf("selected %s, want newest %s", selected.ID, newerExpired.ID)
	}
	if err := ValidateForWorkspace(context.Background(), selected, config.Config{}, config.Workspace{}, newerExpired.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("newest expired validation = %v", err)
	}
}

func TestProjectStoreBreaksCreatedAtTiesByStableID(t *testing.T) {
	root := t.TempDir()
	store, err := ProjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first := testSnapshotForRoot(t, root, now, time.Hour)
	second := testSnapshotForRoot(t, root, now, time.Hour)
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(second); err != nil {
		t.Fatal(err)
	}
	selected, err := store.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	want := first.ID
	if second.ID > want {
		want = second.ID
	}
	if selected.ID != want {
		t.Fatalf("tie selected %s, want lexicographically newest %s", selected.ID, want)
	}
}

func TestProjectStoreRejectsCrossProjectSnapshotCopy(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	first, err := ProjectStore(firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProjectStore(secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshotForRoot(t, firstRoot, time.Now(), time.Hour)
	if err := first.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := second.ensureDir(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(first.path(snapshot.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second.path(snapshot.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Load(snapshot.ID); !errors.Is(err, ErrStale) {
		t.Fatalf("cross-project load error = %v, want stale", err)
	}
}

func TestProjectStoreLatestFailsClosedOnMalformedRecognizedSnapshot(t *testing.T) {
	root := t.TempDir()
	store, err := ProjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	valid := testSnapshotForRoot(t, root, time.Now(), time.Hour)
	if err := store.Save(valid); err != nil {
		t.Fatal(err)
	}
	malformedID := "abcdefghijklmnopqrstuv"
	if err := os.WriteFile(store.path(malformedID), []byte(`{"format":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadLatest(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("latest malformed error = %v, want invalid", err)
	}
}

func TestProjectStoreRejectsSymlinkPermissiveAndOversizedSnapshotFiles(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, path string) {
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"permissive", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, path string) {
			if err := os.WriteFile(path, make([]byte, maxSnapshotBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store, err := ProjectStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.ensureDir(); err != nil {
				t.Fatal(err)
			}
			id := "abcdefghijklmnopqrstuv"
			test.setup(t, store.path(id))
			if _, err := store.Load(id); err == nil {
				t.Fatalf("%s snapshot file was accepted", test.name)
			}
		})
	}
}

func TestProjectStoreCleanupRemovesOnlyExpiredRecognizedSnapshots(t *testing.T) {
	root := t.TempDir()
	store, err := ProjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expired := testSnapshotForRoot(t, root, now.Add(-2*time.Hour), time.Hour)
	current := testSnapshotForRoot(t, root, now, time.Hour)
	for _, snapshot := range []Snapshot{expired, current} {
		if err := store.Save(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(store.Dir, "notes.txt")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformedID := "abcdefghijklmnopqrstuv"
	malformed := store.path(malformedID)
	if err := os.WriteFile(malformed, []byte(`{"format":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	diagnostics, err := store.CleanupExpired(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) < 2 {
		t.Fatalf("cleanup diagnostics = %v", diagnostics)
	}
	if _, err := os.Lstat(store.path(expired.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired snapshot remains: %v", err)
	}
	for _, path := range []string{store.path(current.ID), unknown, malformed} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("preserved entry %s: %v", path, err)
		}
	}
}

func TestProjectStoreBoundsDirectoryEnumeration(t *testing.T) {
	root := t.TempDir()
	store, err := ProjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ensureDir(); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxSnapshotEntries; index++ {
		name := filepath.Join(store.Dir, fmt.Sprintf("unknown-%03d", index))
		if err := os.WriteFile(name, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.LoadLatest(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded enumeration error = %v", err)
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
		{"scan-only requirements kind", func(snapshot *Snapshot) { snapshot.Candidates[0].Kind = "requirements" }},
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
