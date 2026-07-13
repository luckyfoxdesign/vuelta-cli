package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// DigestResolver resolves the current registry digest for an image
// reference's tag (e.g. "python:3.12-slim" -> "sha256:...").
type DigestResolver func(ctx context.Context, ref string) (digest string, err error)

// ResolveDigestViaManifest shells out to `docker manifest inspect --verbose
// <ref>` and extracts the manifest digest. It only reads registry metadata
// — it never pulls or executes the image.
func ResolveDigestViaManifest(ctx context.Context, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "manifest", "inspect", "--verbose", ref)
	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
	}
	digest, err := parseManifestDigest(out)
	if err != nil {
		return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
	}
	return digest, nil
}

func parseManifestDigest(data []byte) (string, error) {
	var single struct {
		Descriptor struct {
			Digest string `json:"digest"`
		} `json:"Descriptor"`
	}
	if err := json.Unmarshal(data, &single); err == nil && single.Descriptor.Digest != "" {
		return single.Descriptor.Digest, nil
	}

	var list []struct {
		Descriptor struct {
			Digest string `json:"digest"`
		} `json:"Descriptor"`
	}
	if err := json.Unmarshal(data, &list); err == nil {
		for _, item := range list {
			if item.Descriptor.Digest != "" {
				return item.Descriptor.Digest, nil
			}
		}
	}

	return "", fmt.Errorf("no manifest digest found in output")
}

// DockerImageUpdater bumps only the digest of pinned FROM/image references
// in the project-relative files listed by Files, keeping each reference's
// tag unchanged. Files come from a workspace's already-validated
// docker_images.files (config.Validate rejects paths outside the project,
// symlinks, and non-regular files).
type DockerImageUpdater struct {
	Files   []string
	Resolve DigestResolver
}

var (
	fromLinePattern  = regexp.MustCompile(`(?i)^(\s*FROM\s+)(\S+?)(@sha256:[0-9a-f]{64})?(\s.*)?$`)
	imageLinePattern = regexp.MustCompile(`^(\s*image:\s*)(\S+?)(@sha256:[0-9a-f]{64})?(\s*#.*)?$`)
)

func (u DockerImageUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	changed := false
	for _, rel := range u.Files {
		path := filepath.Join(projectPath, rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return changed, fmt.Errorf("read %s: %w", rel, err)
		}
		updated, fileChanged, err := u.updateContent(ctx, string(data))
		if err != nil {
			return changed, fmt.Errorf("%s: %w", rel, err)
		}
		if fileChanged {
			if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
				return changed, fmt.Errorf("write %s: %w", rel, err)
			}
			changed = true
		}
	}
	return changed, nil
}

func (u DockerImageUpdater) updateContent(ctx context.Context, content string) (string, bool, error) {
	changed := false
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := fromLinePattern.FindStringSubmatch(line)
		if m == nil {
			m = imageLinePattern.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}

		prefix, tag, suffix := m[1], m[2], m[4]
		digest, err := u.Resolve(ctx, tag)
		if err != nil {
			return content, false, fmt.Errorf("resolve digest for %s: %w", tag, err)
		}
		newRef := tag + "@" + digest
		oldRef := tag + m[3]
		if newRef != oldRef {
			lines[i] = prefix + newRef + suffix
			changed = true
		}
	}
	return strings.Join(lines, "\n"), changed, nil
}
