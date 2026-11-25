package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

// DigestResolver resolves the current registry digest for an image
// reference's tag (e.g. "python:3.12-slim" -> "sha256:...").
type DigestResolver func(ctx context.Context, ref string) (digest string, err error)

// PlatformDigestResolver resolves the immutable manifest selected for one
// exact OS/architecture. Multi-platform tags must not be pinned to whichever
// descriptor happens to appear first in registry output.
type PlatformDigestResolver func(ctx context.Context, ref, platform string) (digest string, err error)

// ResolveDigestViaManifest shells out to `docker manifest inspect --verbose
// <ref>` and extracts the manifest digest. It only reads registry metadata
// — it never pulls or executes the image.
func ResolveDigestViaManifest(ctx context.Context, ref string) (string, error) {
	return DigestResolverWithDocker(dockerexec.Default())(ctx, ref)
}

// DigestResolverWithDocker returns a manifest resolver bound to docker.
func DigestResolverWithDocker(docker dockerexec.Runner) DigestResolver {
	return func(ctx context.Context, ref string) (string, error) {
		result, err := docker.Run(ctx, dockerexec.Request{
			Args:   []string{"manifest", "inspect", "--verbose", ref},
			Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: discoveryOutputMaxBytes},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}
			return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
		}
		digest, err := parseManifestDigest(result.Stdout)
		if err != nil {
			return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
		}
		return digest, nil
	}
}

// ResolveDigestForPlatformViaManifest resolves one exact platform manifest
// through the hardened Docker CLI boundary.
func ResolveDigestForPlatformViaManifest(ctx context.Context, ref, platform string) (string, error) {
	return PlatformDigestResolverWithDocker(dockerexec.Default())(ctx, ref, platform)
}

// PlatformDigestResolverWithDocker returns a platform-aware resolver bound to docker.
func PlatformDigestResolverWithDocker(docker dockerexec.Runner) PlatformDigestResolver {
	return func(ctx context.Context, ref, platform string) (string, error) {
		result, err := docker.Run(ctx, dockerexec.Request{
			Args:   []string{"manifest", "inspect", "--verbose", ref},
			Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: discoveryOutputMaxBytes},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}
			return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
		}
		digest, err := parseManifestDigestForPlatform(result.Stdout, platform)
		if err != nil {
			return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
		}
		return digest, nil
	}
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

func parseManifestDigestForPlatform(data []byte, platform string) (string, error) {
	wantedOS, wantedArch, ok := strings.Cut(platform, "/")
	if !ok || wantedOS == "" || wantedArch == "" || strings.Contains(wantedArch, "/") {
		return "", fmt.Errorf("invalid platform %q", platform)
	}
	type item struct {
		Descriptor struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"Descriptor"`
	}
	var list []item
	if err := json.Unmarshal(data, &list); err == nil {
		for _, candidate := range list {
			if candidate.Descriptor.Platform.OS == wantedOS && candidate.Descriptor.Platform.Architecture == wantedArch && candidate.Descriptor.Digest != "" {
				return candidate.Descriptor.Digest, nil
			}
		}
	}
	var single item
	if err := json.Unmarshal(data, &single); err == nil && single.Descriptor.Digest != "" &&
		single.Descriptor.Platform.OS == wantedOS && single.Descriptor.Platform.Architecture == wantedArch {
		return single.Descriptor.Digest, nil
	}
	return "", fmt.Errorf("no manifest digest found for platform %s", platform)
}
