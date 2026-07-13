// Package tasks creates and reads immutable deploy candidates. It never
// deploys anything: delivery verification and rollback are owned by the
// production worker.
package tasks

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

const schemaVersion = 1

var (
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	projectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Candidate is the versioned, append-only handoff contract for a production
// worker. The image and manifest are immutable digests, never mutable tags.
type Candidate struct {
	Version        int       `json:"version"`
	ID             string    `json:"id"`
	Project        string    `json:"project"`
	CommitSHA      string    `json:"commit_sha"`
	ImageDigest    string    `json:"image_digest"`
	ManifestDigest string    `json:"manifest_digest"`
	Timestamp      time.Time `json:"timestamp"`
	Status         string    `json:"status"`
	Attempt        int       `json:"attempt"`
}

// CreateInput is deliberately explicit: a caller must supply the digests
// produced by the verified build/scan stage, rather than deriving them from a
// branch or a mutable image tag.
type CreateInput struct {
	Project        string
	CommitSHA      string
	ImageDigest    string
	ManifestDigest string
	RepoPath       string
	Remote         string
}

// Creator creates candidates through a configured transport.
type Creator struct {
	Config config.DeployTaskConfig
	Now    func() time.Time
	Random io.Reader
}

func (c Creator) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c Creator) random() io.Reader {
	if c.Random != nil {
		return c.Random
	}
	return rand.Reader
}

// Create creates a candidate exactly once for project+commit+image.
func (c Creator) Create(ctx context.Context, in CreateInput) (Candidate, bool, error) {
	if err := validateInput(in); err != nil {
		return Candidate{}, false, err
	}
	switch c.Config.Mode {
	case "queue_file":
		return c.appendQueue(in)
	case "git_tag":
		return c.createTag(ctx, in)
	default:
		return Candidate{}, false, fmt.Errorf("unsupported deploy task mode %q", c.Config.Mode)
	}
}

func validateInput(in CreateInput) error {
	if !projectPattern.MatchString(in.Project) {
		return fmt.Errorf("invalid project %q", in.Project)
	}
	if !shaPattern.MatchString(in.CommitSHA) {
		return errors.New("commit SHA must be a 40-64 character lowercase hex digest")
	}
	if !digestPattern.MatchString(in.ImageDigest) {
		return errors.New("image digest must be sha256:<64 lowercase hex characters>")
	}
	if !digestPattern.MatchString(in.ManifestDigest) {
		return errors.New("manifest digest must be sha256:<64 lowercase hex characters>")
	}
	return nil
}

// ValidateCandidate checks a candidate received by a production worker before
// it can be used to select an artifact. Transport authentication is separate:
// a structurally valid candidate is not, by itself, authorized to deploy.
func ValidateCandidate(candidate Candidate) error {
	if candidate.Version != schemaVersion {
		return fmt.Errorf("unsupported task schema version %d", candidate.Version)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(candidate.ID) {
		return errors.New("candidate ID must be 32 lowercase hex characters")
	}
	if candidate.Timestamp.IsZero() {
		return errors.New("candidate timestamp is required")
	}
	if candidate.Status != "pending" {
		return fmt.Errorf("candidate status must be pending, got %q", candidate.Status)
	}
	if candidate.Attempt != 0 {
		return errors.New("new candidate attempt must be zero")
	}
	return validateInput(CreateInput{
		Project: candidate.Project, CommitSHA: candidate.CommitSHA,
		ImageDigest: candidate.ImageDigest, ManifestDigest: candidate.ManifestDigest,
	})
}

func (c Creator) newCandidate(in CreateInput) (Candidate, error) {
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(c.random(), idBytes); err != nil {
		return Candidate{}, fmt.Errorf("generate candidate ID: %w", err)
	}
	return Candidate{
		Version: schemaVersion, ID: hex.EncodeToString(idBytes), Project: in.Project,
		CommitSHA: in.CommitSHA, ImageDigest: in.ImageDigest, ManifestDigest: in.ManifestDigest,
		Timestamp: c.now(), Status: "pending", Attempt: 0,
	}, nil
}

func sameIdentity(a Candidate, in CreateInput) bool {
	return a.Project == in.Project && a.CommitSHA == in.CommitSHA && a.ImageDigest == in.ImageDigest
}

func (c Creator) appendQueue(in CreateInput) (Candidate, bool, error) {
	path, err := expandHome(c.Config.QueueFile)
	if err != nil {
		return Candidate{}, false, err
	}
	if existing, ok, err := findQueueCandidate(path, in); err != nil || ok {
		return existing, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Candidate{}, false, fmt.Errorf("create task queue directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return Candidate{}, false, fmt.Errorf("restrict task queue directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return Candidate{}, false, errors.New("task queue must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return Candidate{}, false, fmt.Errorf("stat task queue: %w", err)
	}
	candidate, err := c.newCandidate(in)
	if err != nil {
		return Candidate{}, false, err
	}
	line, err := json.Marshal(candidate)
	if err != nil {
		return Candidate{}, false, fmt.Errorf("encode deploy candidate: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Candidate{}, false, fmt.Errorf("open task queue: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return Candidate{}, false, fmt.Errorf("restrict task queue: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Candidate{}, false, fmt.Errorf("append deploy candidate: %w", err)
	}
	if err := f.Sync(); err != nil {
		return Candidate{}, false, fmt.Errorf("sync deploy candidate: %w", err)
	}
	return candidate, true, nil
}

// ListPending returns pending candidates in queue-file mode.
func ListPending(queueFile string) ([]Candidate, error) {
	path, err := expandHome(queueFile)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open task queue: %w", err)
	}
	defer func() { _ = f.Close() }()
	var candidates []Candidate
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		var candidate Candidate
		if err := json.Unmarshal(s.Bytes(), &candidate); err != nil {
			return nil, fmt.Errorf("decode task queue: %w", err)
		}
		if candidate.Version != schemaVersion {
			return nil, fmt.Errorf("unsupported task schema version %d", candidate.Version)
		}
		if candidate.Status == "pending" {
			candidates = append(candidates, candidate)
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read task queue: %w", err)
	}
	return candidates, nil
}

func findQueueCandidate(path string, in CreateInput) (Candidate, bool, error) {
	candidates, err := ListPending(path)
	if err != nil {
		return Candidate{}, false, err
	}
	for _, candidate := range candidates {
		if sameIdentity(candidate, in) {
			return candidate, true, nil
		}
	}
	return Candidate{}, false, nil
}

func (c Creator) createTag(ctx context.Context, in CreateInput) (Candidate, bool, error) {
	if in.RepoPath == "" || in.Remote == "" {
		return Candidate{}, false, errors.New("git_tag mode requires repo path and remote")
	}
	if existing, ok, err := findTagCandidate(ctx, in.RepoPath, c.Config.TagPrefix, in); err != nil || ok {
		return existing, false, err
	}
	candidate, err := c.newCandidate(in)
	if err != nil {
		return Candidate{}, false, err
	}
	tag := fmt.Sprintf("%s/%s-%s", strings.TrimSuffix(c.Config.TagPrefix, "/"), in.Project, candidate.Timestamp.Format("20060102T150405Z"))
	payload, err := json.Marshal(candidate)
	if err != nil {
		return Candidate{}, false, fmt.Errorf("encode signed tag payload: %w", err)
	}
	if _, err := git(ctx, in.RepoPath, "tag", "-s", "-a", tag, in.CommitSHA, "-m", string(payload)); err != nil {
		return Candidate{}, false, fmt.Errorf("create signed deploy tag: %w", err)
	}
	if _, err := git(ctx, in.RepoPath, "push", in.Remote, "refs/tags/"+tag); err != nil {
		return Candidate{}, false, fmt.Errorf("push signed deploy tag: %w", err)
	}
	return candidate, true, nil
}

func findTagCandidate(ctx context.Context, repoPath, prefix string, in CreateInput) (Candidate, bool, error) {
	pattern := "refs/tags/" + strings.TrimSuffix(prefix, "/") + "/" + in.Project + "-*"
	out, err := git(ctx, repoPath, "for-each-ref", "--format=%(refname:short)", pattern)
	if err != nil {
		return Candidate{}, false, fmt.Errorf("list deploy tags: %w", err)
	}
	for _, tag := range strings.Fields(string(out)) {
		content, err := git(ctx, repoPath, "for-each-ref", "--format=%(contents)", "refs/tags/"+tag)
		if err != nil {
			return Candidate{}, false, fmt.Errorf("read deploy tag %s: %w", tag, err)
		}
		candidate, ok := candidateFromTagContent(string(content))
		if ok && sameIdentity(candidate, in) {
			return candidate, true, nil
		}
	}
	return Candidate{}, false, nil
}

func candidateFromTagContent(content string) (Candidate, bool) {
	start, end := strings.IndexByte(content, '{'), strings.LastIndexByte(content, '}')
	if start < 0 || end < start {
		return Candidate{}, false
	}
	var candidate Candidate
	if err := json.Unmarshal([]byte(content[start:end+1]), &candidate); err != nil || candidate.Version != schemaVersion {
		return Candidate{}, false
	}
	return candidate, true
}

// ParseTaggedCandidate extracts the JSON candidate from an annotated tag
// message. Callers must still verify the tag's signature and exact target.
func ParseTaggedCandidate(content string) (Candidate, error) {
	candidate, ok := candidateFromTagContent(content)
	if !ok {
		return Candidate{}, errors.New("annotated tag does not contain a valid deploy candidate")
	}
	return candidate, nil
}

func git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("git %s: %w", strings.Join(args[:min(3, len(args))], " "), err)
	}
	return out, nil
}

func expandHome(path string) (string, error) {
	if path == "" {
		return "", errors.New("task queue path is required")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
