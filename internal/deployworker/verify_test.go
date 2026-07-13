package deployworker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedQueueRejectsForgedRecord(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := candidate("77777777777777777777777777777777")
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	valid := signedCandidate{Candidate: c, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))}
	forged := valid
	forged.Candidate.CommitSHA = "1123456789abcdef0123456789abcdef01234567"
	data, _ := json.Marshal(valid)
	bad, _ := json.Marshal(forged)
	dir := filepath.Join(t.TempDir(), "queue")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "queue.jsonl")
	if err := os.WriteFile(path, append(append(data, '\n'), append(bad, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	source := SignedQueueSource{Path: path, PublicKey: public}
	deliveries, err := source.Pending(context.Background())
	if err != nil || len(deliveries) != 2 || !deliveries[0].Authenticated || deliveries[1].Authenticated {
		t.Fatalf("Pending = %#v, %v", deliveries, err)
	}
}

func TestManifestVerifierBindsSignedManifestToCandidate(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := candidate("88888888888888888888888888888888")
	m := Manifest{Version: 1, CandidateID: c.ID, Project: c.Project, CommitSHA: c.CommitSHA, ImageDigest: c.ImageDigest, Platform: "linux/amd64", SBOMDigest: testPrevious, CVESummary: "no-high", CreatedAt: time.Now().UTC()}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signedManifest{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	c.ManifestDigest = "sha256:" + hex.EncodeToString(sum[:])
	v := Ed25519ManifestVerifier{PublicKey: public, Load: func(context.Context, string) ([]byte, error) { return raw, nil }}
	if err := v.Verify(context.Background(), c, Project{Name: "api", ImageRepository: "registry.example/api"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	c.CommitSHA = "1123456789abcdef0123456789abcdef01234567"
	if err := v.Verify(context.Background(), c, Project{Name: "api", ImageRepository: "registry.example/api"}); err == nil {
		t.Fatal("expected manifest/candidate mismatch to be rejected")
	}
	c.CommitSHA = m.CommitSHA
	c.ImageDigest = testPrevious
	if err := v.Verify(context.Background(), c, Project{Name: "api", ImageRepository: "registry.example/api"}); err == nil {
		t.Fatal("expected wrong image digest to be rejected")
	}
}

func TestGitTagSourceRejectsUnsignedOrWrongTargetTag(t *testing.T) {
	c := candidate("99999999999999999999999999999999")
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	tag := "deploy-pending/api-20260714T000000Z"
	tagCommit := c.CommitSHA
	source := GitTagSource{
		Repository: "/var/lib/vuelta/tag-mirror.git", Remote: "origin", ExpectedOrigin: "ssh://git.example/vuelta.git",
		TagPrefix: "deploy-pending", TrustedFingerprint: "FINGERPRINT",
		Run: func(_ context.Context, _ string, args ...string) (string, error) {
			switch {
			case args[0] == "remote":
				return "ssh://git.example/vuelta.git\n", nil
			case args[0] == "for-each-ref" && strings.Contains(args[len(args)-1], "refs/tags/deploy-pending/*"):
				return tag + "\n", nil
			case args[0] == "for-each-ref":
				return "deploy candidate\n" + string(payload), nil
			case args[0] == "verify-tag":
				return "[GNUPG:] VALIDSIG FINGERPRINT\n", nil
			case args[0] == "rev-parse" && strings.HasSuffix(args[len(args)-1], "^{commit}"):
				return tagCommit + "\n", nil
			case args[0] == "rev-parse":
				return "tag-object-id\n", nil
			case args[0] == "ls-remote":
				return "tag-object-id\trefs/tags/" + tag + "\n", nil
			default:
				return "", errors.New("unexpected git call")
			}
		},
	}
	deliveries, err := source.Pending(context.Background())
	if err != nil || len(deliveries) != 1 || !deliveries[0].Authenticated {
		t.Fatalf("Pending = %#v, %v", deliveries, err)
	}
	source.TrustedFingerprint = "DIFFERENT"
	deliveries, err = source.Pending(context.Background())
	if err != nil || deliveries[0].Authenticated {
		t.Fatalf("forged tag was accepted: %#v, %v", deliveries, err)
	}
	source.TrustedFingerprint = "FINGERPRINT"
	tagCommit = "1123456789abcdef0123456789abcdef01234567"
	deliveries, err = source.Pending(context.Background())
	if err != nil || deliveries[0].Authenticated {
		t.Fatalf("wrong-target tag was accepted: %#v, %v", deliveries, err)
	}
}
