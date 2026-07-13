package deployworker

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/tasks"
)

// GitTagSource reads signed annotated candidates from a pre-provisioned bare
// mirror. It never fetches a branch or changes a source checkout. The worker
// checks the configured origin, tag reference, signature fingerprint, and tag
// commit target before accepting a delivery.
type GitTagSource struct {
	Repository         string
	Remote             string
	ExpectedOrigin     string
	TagPrefix          string
	TrustedFingerprint string
	Run                func(context.Context, string, ...string) (string, error)
}

func (s GitTagSource) git(ctx context.Context, args ...string) (string, error) {
	if s.Run != nil {
		return s.Run(ctx, s.Repository, args...)
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = s.Repository
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("git tag verification command failed")
	}
	return string(out), nil
}

// Pending implements Source. A bad tag becomes an unauthenticated delivery
// when it contains a parseable candidate, so the state records the rejection.
func (s GitTagSource) Pending(ctx context.Context) ([]Delivery, error) {
	if s.Repository == "" || s.Remote == "" || s.ExpectedOrigin == "" || s.TagPrefix == "" || s.TrustedFingerprint == "" {
		return nil, errors.New("git tag source is incomplete")
	}
	origin, err := s.git(ctx, "remote", "get-url", s.Remote)
	if err != nil {
		return nil, fmt.Errorf("read git tag origin: %w", err)
	}
	if strings.TrimSpace(origin) != s.ExpectedOrigin {
		return nil, errors.New("git tag origin does not match configured origin")
	}
	tags, err := s.git(ctx, "for-each-ref", "--format=%(refname:short)", "refs/tags/"+strings.TrimSuffix(s.TagPrefix, "/")+"/*")
	if err != nil {
		return nil, fmt.Errorf("list deploy tags: %w", err)
	}
	var deliveries []Delivery
	for _, tag := range strings.Fields(tags) {
		delivery, err := s.delivery(ctx, tag)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, nil
}

func (s GitTagSource) delivery(ctx context.Context, tag string) (Delivery, error) {
	content, err := s.git(ctx, "for-each-ref", "--format=%(contents)", "refs/tags/"+tag)
	if err != nil {
		return Delivery{}, fmt.Errorf("read deploy tag %s: %w", tag, err)
	}
	candidate, parseErr := tasks.ParseTaggedCandidate(content)
	if parseErr != nil {
		return Delivery{}, nil
	}
	signature, signatureErr := s.git(ctx, "verify-tag", "--raw", tag)
	commit, commitErr := s.git(ctx, "rev-parse", "--verify", tag+"^{commit}")
	remoteRef, remoteErr := s.git(ctx, "ls-remote", "--tags", s.Remote, "refs/tags/"+tag)
	localRef, localErr := s.git(ctx, "rev-parse", "--verify", tag+"^{tag}")
	authenticated := signatureErr == nil && commitErr == nil && remoteErr == nil && localErr == nil &&
		trustedSignature(signature, s.TrustedFingerprint) && strings.TrimSpace(commit) == candidate.CommitSHA && exactRemoteTag(remoteRef, localRef)
	return Delivery{Candidate: candidate, Authenticated: authenticated}, nil
}

func trustedSignature(raw, fingerprint string) bool {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "VALIDSIG" && i+1 < len(fields) && strings.EqualFold(fields[i+1], fingerprint) {
				return true
			}
		}
	}
	return false
}

func exactRemoteTag(remote, local string) bool {
	fields := strings.Fields(remote)
	return len(fields) >= 2 && strings.TrimSpace(local) != "" && fields[0] == strings.TrimSpace(local)
}
