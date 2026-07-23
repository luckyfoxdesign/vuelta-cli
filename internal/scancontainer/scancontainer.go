// Package scancontainer runs a scanner against an in-memory input archive.
// Repository contents are copied into a stopped container through Docker's
// stdin API; no host path is mounted and no host staging copy is created.
package scancontainer

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

const cleanupTimeout = 15 * time.Second

var (
	exactDigest   = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	localImageID  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dockerName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	safeSizeFlag  = regexp.MustCompile(`^[1-9][0-9]*(k|m|g)$`)
	containerUser = regexp.MustCompile(`^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$`)
)

// Request describes one hardened scanner container lifecycle.
type Request struct {
	Image    string
	Platform string
	User     string
	Args     []string
	Archive  []byte
	Network  string
	Proxy    string
	Tool     string
	Memory   string
	Tmpfs    string
	Stdout   dockerexec.Capture
	Stderr   dockerexec.Capture
	Combined dockerexec.Capture
}

// Runner owns the create/copy/start/remove lifecycle. Tests inject Docker and
// NewName; production uses cryptographically random opaque names.
type Runner struct {
	Docker  dockerexec.Runner
	NewName func() (string, error)
}

// Run copies inputs into a stopped loader that is never executed, commits its
// private layer to an ephemeral local image, and starts a separate final
// scanner with the full read-only hardening. Every resource has an opaque name
// and is removed with an independent bounded cleanup context.
func (r Runner) Run(ctx context.Context, request Request) (result dockerexec.Result, err error) {
	if err := validateRequest(request); err != nil {
		return dockerexec.Result{}, err
	}
	docker := r.Docker
	if docker == nil {
		docker = dockerexec.Default()
	}
	name, err := r.newName()
	if err != nil {
		return dockerexec.Result{}, err
	}
	loaderName := name + "-loader"
	imageName := "vuelta-scan-input:" + strings.TrimPrefix(name, "vuelta-scan-")
	loaderCreated := false
	imageCreated := false
	finalCreated := false
	defer func() {
		if !loaderCreated && !imageCreated && !finalCreated {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		var cleanupErr error
		for _, resource := range []struct {
			attempted bool
			args      []string
		}{
			{finalCreated, []string{"rm", "-f", name}},
			{loaderCreated, []string{"rm", "-f", loaderName}},
			{imageCreated, []string{"image", "rm", "-f", imageName}},
		} {
			if !resource.attempted {
				continue
			}
			if _, removeErr := docker.Run(cleanupCtx, dockerexec.Request{
				Args: resource.args, Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
			}); removeErr != nil {
				cleanupErr = errors.Join(cleanupErr, removeErr)
			}
		}
		if cleanupErr != nil {
			err = errors.Join(err, errors.New("remove ephemeral scanner resources"))
		}
	}()

	loaderArgs := []string{"create", "--name", loaderName, "--network", "none"}
	if request.Platform != "" {
		loaderArgs = append(loaderArgs, "--platform", request.Platform)
	}
	loaderArgs = append(loaderArgs, request.Image)
	if _, err := docker.Run(ctx, dockerexec.Request{
		// Docker may fetch the exact digest before this stopped loader exists;
		// repository input is copied only after create succeeds. The loader is
		// never started and therefore cannot execute image code.
		Args:   loaderArgs,
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return dockerexec.Result{}, fmt.Errorf("create stopped scanner input loader: %w", err)
	}
	loaderCreated = true
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args: []string{"cp", "-a", "-", loaderName + ":/"}, Stdin: bytes.NewReader(request.Archive),
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return dockerexec.Result{}, fmt.Errorf("copy scanner input archive: %w", err)
	}
	commitResult, err := docker.Run(ctx, dockerexec.Request{
		// Pausing is Docker's default. Passing the deprecated --pause flag makes
		// recent CLIs write a warning before the image ID and breaks the strict,
		// bounded machine-output contract below.
		Args:   []string{"commit", loaderName, imageName},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 128},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return dockerexec.Result{}, fmt.Errorf("commit ephemeral scanner input image: %w", err)
	}
	imageCreated = true
	imageID := strings.TrimSpace(string(commitResult.Stdout))
	if !localImageID.MatchString(imageID) {
		return dockerexec.Result{}, errors.New("commit ephemeral scanner input image returned an invalid ID")
	}
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"rm", "-f", loaderName},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return dockerexec.Result{}, fmt.Errorf("remove stopped scanner input loader: %w", err)
	}
	loaderCreated = false
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args:   createArgs(name, imageID, request),
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return dockerexec.Result{}, fmt.Errorf("create final read-only scanner container: %w", err)
	}
	finalCreated = true
	result, err = docker.Run(ctx, dockerexec.Request{
		Args: []string{"start", "-a", name}, Stdout: request.Stdout, Stderr: request.Stderr, Combined: request.Combined,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		return result, fmt.Errorf("start scanner container: %w", err)
	}
	return result, nil
}

func (r Runner) newName() (string, error) {
	if r.NewName != nil {
		name, err := r.NewName()
		if err != nil {
			return "", err
		}
		if !dockerName.MatchString(name) || len(name) > 120 {
			return "", errors.New("generated scanner container name is invalid")
		}
		return name, nil
	}
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", fmt.Errorf("generate scanner container name: %w", err)
	}
	return "vuelta-scan-" + hex.EncodeToString(random), nil
}

func validateRequest(request Request) error {
	if !exactDigest.MatchString(request.Image) && !localImageID.MatchString(request.Image) {
		return fmt.Errorf("scanner image %q is not pinned to an exact digest", request.Image)
	}
	if !dockerName.MatchString(request.Network) {
		return errors.New("scanner network name is invalid")
	}
	proxy, err := url.Parse(request.Proxy)
	if err != nil || proxy.Scheme != "http" || proxy.Host == "" || proxy.User != nil || proxy.RawQuery != "" || proxy.Fragment != "" {
		return errors.New("scanner proxy URL is invalid")
	}
	if request.Tool != "" && request.Tool != "trivy" {
		return errors.New("scanner tool environment is not allowlisted")
	}
	if request.User != "" && !containerUser.MatchString(request.User) {
		return errors.New("scanner user must be an explicit non-root numeric uid:gid")
	}
	if request.Platform != "" && request.Platform != "linux/amd64" && request.Platform != "linux/arm64" {
		return errors.New("scanner platform must be linux/amd64 or linux/arm64")
	}
	if !safeSizeFlag.MatchString(request.Memory) || !safeSizeFlag.MatchString(request.Tmpfs) {
		return errors.New("scanner resource limit is invalid")
	}
	if len(request.Archive) == 0 || len(request.Archive) > 40<<20 {
		return errors.New("scanner input archive size is invalid")
	}
	return validateArchive(request.Archive)
}

func validateArchive(data []byte) error {
	r := tar.NewReader(bytes.NewReader(data))
	entries := 0
	var total int64
	seen := make(map[string]bool)
	for {
		header, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("scanner input archive is invalid")
		}
		entries++
		if entries > 64 || header.Name == "" || strings.Contains(header.Name, "\\") || path.IsAbs(header.Name) {
			return errors.New("scanner input archive entry is invalid")
		}
		clean := path.Clean(header.Name)
		if clean != "project" && !strings.HasPrefix(clean, "project/") {
			return errors.New("scanner input archive entry escapes project")
		}
		if seen[clean] {
			return errors.New("scanner input archive contains a duplicate entry")
		}
		seen[clean] = true
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != 0 {
			return errors.New("scanner input archive contains a non-regular entry")
		}
		if header.Size < 0 || header.Size > 8<<20 || header.Uid != 65532 || header.Gid != 65532 {
			return errors.New("scanner input archive metadata is invalid")
		}
		total += header.Size
		if total > 32<<20 {
			return errors.New("scanner input archive exceeds total size limit")
		}
	}
	if entries == 0 {
		return errors.New("scanner input archive is empty")
	}
	return nil
}

func createArgs(name, image string, request Request) []string {
	proxy := request.Proxy
	user := request.User
	if user == "" {
		user = "65532:65532"
	}
	args := []string{
		"create", "--name", name, "--pull", "never",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "1",
		"--memory", request.Memory,
		"--pids-limit", "256",
		"--network", request.Network,
		"--env", "HTTP_PROXY=" + proxy,
		"--env", "HTTPS_PROXY=" + proxy,
		"--env", "http_proxy=" + proxy,
		"--env", "https_proxy=" + proxy,
		"--env", "NO_PROXY=localhost,127.0.0.1",
		"--env", "HOME=/tmp",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=" + request.Tmpfs,
		"--workdir", "/project",
	}
	if request.Platform != "" {
		args = append(args, "--platform", request.Platform)
	}
	args = append(args, "--user", user)
	if request.Tool == "trivy" {
		args = append(args,
			"--env", "TRIVY_CACHE_DIR=/tmp/trivy",
			"--env", "TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db",
		)
	}
	args = append(args, image)
	return append(args, request.Args...)
}
