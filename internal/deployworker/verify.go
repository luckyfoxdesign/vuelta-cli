package deployworker

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/tasks"
)

// StaticSource is useful for an explicitly supplied, already verified batch
// and for deterministic tests. Production queue and tag integrations should
// set Authenticated only after cryptographic verification.
type StaticSource struct{ Deliveries []Delivery }

// Pending returns a copy so a caller cannot mutate the source while a worker
// is processing it.
func (s StaticSource) Pending(context.Context) ([]Delivery, error) {
	return append([]Delivery(nil), s.Deliveries...), nil
}

// SignedQueueSource reads newline-delimited signed candidate envelopes. The
// queue must be delivered into a private local directory by the transport;
// unsigned records from the legacy handoff queue are intentionally rejected.
type SignedQueueSource struct {
	Path      string
	PublicKey ed25519.PublicKey
}

type signedCandidate struct {
	Candidate tasks.Candidate `json:"candidate"`
	Signature string          `json:"signature"`
}

// Pending authenticates every record independently. A malformed or unsigned
// record yields an unauthenticated delivery rather than being silently skipped,
// making the worker record its rejection without changing the service.
func (s SignedQueueSource) Pending(context.Context) ([]Delivery, error) {
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("queue verification public key is invalid")
	}
	info, err := os.Lstat(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat signed candidate queue: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("signed candidate queue must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signed candidate queue must not be group- or world-readable")
	}
	parent, err := os.Stat(filepath.Dir(s.Path))
	if err != nil {
		return nil, fmt.Errorf("stat signed candidate queue directory: %w", err)
	}
	if parent.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signed candidate queue directory must not be group- or world-readable")
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, fmt.Errorf("open signed candidate queue: %w", err)
	}
	defer func() { _ = f.Close() }()
	var deliveries []Delivery
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var envelope signedCandidate
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			deliveries = append(deliveries, Delivery{})
			continue
		}
		signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
		payload, marshalErr := json.Marshal(envelope.Candidate)
		deliveries = append(deliveries, Delivery{Candidate: envelope.Candidate,
			Authenticated: err == nil && marshalErr == nil && ed25519.Verify(s.PublicKey, payload, signature),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read signed candidate queue: %w", err)
	}
	return deliveries, nil
}

// Manifest records the security-gated build facts that must match a candidate.
// The SBOM/CVE fields are digests/summaries, never full scanner logs.
type Manifest struct {
	Version     int       `json:"version"`
	CandidateID string    `json:"candidate_id"`
	Project     string    `json:"project"`
	CommitSHA   string    `json:"commit_sha"`
	ImageDigest string    `json:"image_digest"`
	Platform    string    `json:"platform"`
	SBOMDigest  string    `json:"sbom_digest"`
	CVESummary  string    `json:"cve_summary"`
	CreatedAt   time.Time `json:"created_at"`
}

type signedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}

// ManifestLoader obtains the exact manifest bytes addressed by digest. The
// implementation is normally an allowlisted registry client; it is injected
// to keep credentials outside worker configuration and code.
type ManifestLoader func(context.Context, string) ([]byte, error)

// Ed25519ManifestVerifier checks both content-addressing and the signature of
// a build manifest. The registry/object fetcher is deliberately separate from
// the deployment adapter so a failed manifest is rejected before service work.
type Ed25519ManifestVerifier struct {
	PublicKey ed25519.PublicKey
	Load      ManifestLoader
}

// Verify implements ArtifactVerifier.
func (v Ed25519ManifestVerifier) Verify(ctx context.Context, candidate tasks.Candidate, project Project) error {
	_ = project // repository selection remains in the allowlisted adapter configuration.
	if len(v.PublicKey) != ed25519.PublicKeySize || v.Load == nil {
		return errors.New("manifest verifier requires an Ed25519 public key and loader")
	}
	raw, err := v.Load(ctx, candidate.ManifestDigest)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	sum := sha256.Sum256(raw)
	if candidate.ManifestDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return errors.New("manifest content does not match candidate digest")
	}
	var envelope signedManifest
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return errors.New("manifest signature is not base64")
	}
	payload, err := json.Marshal(envelope.Manifest)
	if err != nil || !ed25519.Verify(v.PublicKey, payload, signature) {
		return errors.New("manifest signature is invalid")
	}
	m := envelope.Manifest
	if m.Version != 1 || m.CandidateID != candidate.ID || m.Project != candidate.Project || m.CommitSHA != candidate.CommitSHA || m.ImageDigest != candidate.ImageDigest || m.Platform == "" || m.SBOMDigest == "" || m.CVESummary == "" || m.CreatedAt.IsZero() {
		return errors.New("manifest does not match the deployment candidate")
	}
	return nil
}

// DigestFileLoader returns a loader for manifests delivered into a private
// local directory. Files are addressed only by the validated digest hex, so a
// candidate cannot choose an arbitrary filesystem path.
func DigestFileLoader(dir string) ManifestLoader {
	return func(_ context.Context, digest string) ([]byte, error) {
		if !safeDigest(digest) {
			return nil, errors.New("invalid manifest digest")
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("stat manifest directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("manifest directory must be a private real directory")
		}
		path := filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")+".json")
		info, err = os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("stat manifest: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("manifest must be a private regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read manifest: %w", err)
		}
		return data, nil
	}
}
