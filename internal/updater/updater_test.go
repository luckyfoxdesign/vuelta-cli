package updater

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunDockerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := RunDocker(ctx, "example.invalid/image", nil, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestResolveDigestViaManifestHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ResolveDigestViaManifest(ctx, "example.invalid/image:latest")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRunDockerFailsClosedWithoutEgressPolicy(t *testing.T) {
	_, err := RunDocker(context.Background(), "node@sha256:x", []string{"npm", "install"}, t.TempDir())
	if !errors.Is(err, ErrEgressPolicyUnavailable) {
		t.Fatalf("expected ErrEgressPolicyUnavailable, got %v", err)
	}
}

func TestDockerRunArgsIncludeSecurityBaseline(t *testing.T) {
	got := dockerRunArgs("node@sha256:x", []string{"npm", "install"}, "/sandbox/project", "vuelta-update-egress", "http://vuelta-egress-proxy:3128")
	for _, want := range []string{
		"--user", "65532:65532",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "1",
		"--memory", "1g",
		"--pids-limit", "256",
		"--network", "vuelta-update-egress",
		"HTTP_PROXY=http://vuelta-egress-proxy:3128",
		"HTTPS_PROXY=http://vuelta-egress-proxy:3128",
		"--env", "HOME=/tmp",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	} {
		if !slicesContain(got, want) {
			t.Fatalf("docker args missing %q: %q", want, got)
		}
	}
	if slicesContain(got, "/var/run/docker.sock") || slicesContain(got, "host") {
		t.Fatalf("docker args must not expose a Docker socket or host namespace: %q", got)
	}
}

func TestDockerRunArgsIncludeProfilePlatform(t *testing.T) {
	got := dockerRunArgsForProfile("node@sha256:x", []string{"npm", "install"}, "/sandbox/project", "vuelta-update-egress", "http://vuelta-egress-proxy:3128", "10001:10001", "linux/arm64")
	if !slicesContain(got, "--platform") || !slicesContain(got, "linux/arm64") {
		t.Fatalf("docker args missing profile platform: %q", got)
	}
}

func TestParseManifestDigestSingle(t *testing.T) {
	data := []byte(`{"Descriptor":{"digest":"sha256:` + strings.Repeat("d", 64) + `"}}`)
	digest, err := parseManifestDigest(data)
	if err != nil {
		t.Fatalf("parseManifestDigest: %v", err)
	}
	if digest != "sha256:"+strings.Repeat("d", 64) {
		t.Fatalf("unexpected digest: %q", digest)
	}
}

func TestParseManifestDigestList(t *testing.T) {
	data := []byte(`[{"Descriptor":{"digest":"sha256:` + strings.Repeat("e", 64) + `"}}]`)
	digest, err := parseManifestDigest(data)
	if err != nil {
		t.Fatalf("parseManifestDigest: %v", err)
	}
	if digest != "sha256:"+strings.Repeat("e", 64) {
		t.Fatalf("unexpected digest: %q", digest)
	}
}

func TestParseManifestDigestForPlatformDoesNotUseFirstDescriptor(t *testing.T) {
	amd64 := "sha256:" + strings.Repeat("a", 64)
	arm64 := "sha256:" + strings.Repeat("b", 64)
	data := []byte(`[
{"Descriptor":{"digest":"` + amd64 + `","platform":{"os":"linux","architecture":"amd64"}}},
{"Descriptor":{"digest":"` + arm64 + `","platform":{"os":"linux","architecture":"arm64"}}}
]`)
	digest, err := parseManifestDigestForPlatform(data, "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if digest != arm64 {
		t.Fatalf("platform digest = %q, want %q", digest, arm64)
	}
	if _, err := parseManifestDigestForPlatform(data, "linux/s390x"); err == nil {
		t.Fatal("missing platform descriptor was accepted")
	}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
