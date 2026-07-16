// Package deployworker applies authenticated, immutable deployment candidates
// and restores the previous digest when a rollout is unhealthy.
package deployworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

// ProjectCompose extends an allowlisted project with its pre-approved Compose
// target and health endpoints. It is configuration, not candidate input.
type ProjectCompose struct {
	Project
	ComposeFile string
	Service     string
	HealthURL   string
	SmokeURL    string
}

// ComposeAdapter deploys a digest through a fixed Compose service. It never
// builds an image, invokes a shell, runs migrations, or writes the compose
// file/.env. The compose file must use ${VUELTA_IMAGE} for the selected
// service image; otherwise the deploy is intentionally ineffective and its
// health check fails closed.
type ComposeAdapter struct {
	Projects map[string]ProjectCompose
	Run      func(context.Context, string, ...string) (string, error)
	Docker   dockerexec.Runner
	Client   *http.Client
}

func (a ComposeAdapter) command(ctx context.Context, name string, args ...string) (string, error) {
	if a.Run != nil {
		return a.Run(ctx, name, args...)
	}
	if name != "docker" {
		return "", errors.New("compose adapter command is not allowlisted")
	}
	docker := a.Docker
	if docker == nil {
		docker = dockerexec.Default()
	}
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   args,
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 1 << 20},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
	})
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("%s failed", name)
	}
	return string(result.Stdout), nil
}

func (a ComposeAdapter) target(project Project) (ProjectCompose, error) {
	target, ok := a.Projects[project.Name]
	if !ok || target.Project != project || target.ComposeFile == "" || target.Service == "" || target.HealthURL == "" || target.SmokeURL == "" {
		return ProjectCompose{}, fmt.Errorf("project %q has no complete compose deploy adapter", project.Name)
	}
	return target, nil
}

func imageReference(project Project, digest string) (string, error) {
	if !safeDigest(digest) || !validImageRepository(project.ImageRepository) {
		return "", errors.New("invalid allowlisted image repository or digest")
	}
	return project.ImageRepository + "@" + digest, nil
}

func validImageRepository(repository string) bool {
	if repository == "" || strings.Contains(repository, "@") || strings.ContainsAny(repository, " \t\n") {
		return false
	}
	lastSlash := strings.LastIndexByte(repository, '/')
	return !strings.Contains(repository[lastSlash+1:], ":")
}

func safeDigest(digest string) bool {
	return len(digest) == len("sha256:")+64 && strings.HasPrefix(digest, "sha256:") && strings.Trim(digest[len("sha256:"):], "0123456789abcdef") == ""
}

// EnsureArtifact pulls exactly repository@digest; a mutable image tag is never
// accepted at this boundary.
func (a ComposeAdapter) EnsureArtifact(ctx context.Context, project Project, digest string) error {
	ref, err := imageReference(project, digest)
	if err != nil {
		return err
	}
	if _, err := a.command(ctx, "docker", "pull", ref); err != nil {
		return fmt.Errorf("pull immutable artifact: %w", err)
	}
	return nil
}

// CurrentDigest obtains the running service's RepoDigest, which becomes the
// rollback target. A service without an immutable RepoDigest is refused.
func (a ComposeAdapter) CurrentDigest(ctx context.Context, project Project) (string, error) {
	target, err := a.target(project)
	if err != nil {
		return "", err
	}
	container, err := a.command(ctx, "docker", "compose", "-f", target.ComposeFile, "ps", "-q", target.Service)
	if err != nil || strings.TrimSpace(container) == "" {
		return "", errors.New("running service container is required to create a rollback target")
	}
	repos, err := a.command(ctx, "docker", "inspect", "--format={{range .RepoDigests}}{{println .}}{{end}}", strings.TrimSpace(container))
	if err != nil {
		return "", fmt.Errorf("inspect running service image: %w", err)
	}
	prefix := project.ImageRepository + "@"
	for _, ref := range strings.Fields(repos) {
		if strings.HasPrefix(ref, prefix) && safeDigest(strings.TrimPrefix(ref, prefix)) {
			return strings.TrimPrefix(ref, prefix), nil
		}
	}
	return "", errors.New("running service image is not the allowlisted immutable repository digest")
}

// Deploy asks Compose to use VUELTA_IMAGE and disables build/dependency work.
func (a ComposeAdapter) Deploy(ctx context.Context, project Project, digest string) error {
	target, err := a.target(project)
	if err != nil {
		return err
	}
	ref, err := imageReference(project, digest)
	if err != nil {
		return err
	}
	args := []string{"compose", "-f", target.ComposeFile, "up", "-d", "--no-build", "--no-deps", target.Service}
	if a.Run != nil {
		if _, err := a.Run(ctx, "docker", args...); err != nil {
			return fmt.Errorf("start digest-pinned service: %w", err)
		}
		return nil
	}
	docker := a.Docker
	if docker == nil {
		docker = dockerexec.Default()
	}
	if _, err := docker.Run(ctx, dockerexec.Request{Args: args, Env: map[string]string{"VUELTA_IMAGE": ref}}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("start digest-pinned service: %w", err)
	}
	return nil
}

// Health performs a small unauthenticated GET; the endpoint is therefore
// required to expose no operational secrets.
func (a ComposeAdapter) Health(ctx context.Context, project Project) error {
	target, err := a.target(project)
	if err != nil {
		return err
	}
	return a.get(ctx, target.HealthURL)
}

// Smoke performs the project's pre-approved minimal HTTP smoke check.
func (a ComposeAdapter) Smoke(ctx context.Context, project Project) error {
	target, err := a.target(project)
	if err != nil {
		return err
	}
	return a.get(ctx, target.SmokeURL)
}

// Rollback starts the previously saved immutable digest through the same
// restricted adapter path as a forward deploy.
func (a ComposeAdapter) Rollback(ctx context.Context, project Project, digest string) error {
	return a.Deploy(ctx, project, digest)
}

func (a ComposeAdapter) get(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("health and smoke URLs must be absolute http(s) URLs")
	}
	if u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1" {
		return errors.New("plain HTTP health and smoke URLs must be loopback-only")
	}
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errors.New("build health request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("perform health request")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health endpoint returned status %d", resp.StatusCode)
	}
	return nil
}
