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
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
)

const cleanupTimeout = 15 * time.Second

var (
	exactDigest   = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	localImageID  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dockerName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	trivyDBVolume = regexp.MustCompile(`^vuelta-trivy-db-[0-9a-f]{16}$`)
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
	// TrivyDBVolume is a Vuelta-owned Docker volume containing only Trivy's
	// verified vulnerability database. It is never derived from project input
	// and is mounted below the otherwise ephemeral /tmp cache.
	TrivyDBVolume string
	// TrivyDBInitialize prepares the managed cache for the non-root scanner
	// before a database download. Trivy needs the cache mount writable even
	// with --skip-db-update because it opens the SQLite database with writable
	// compatibility state.
	TrivyDBInitialize bool
	Memory            string
	Tmpfs             string
	Stdout            dockerexec.Capture
	Stderr            dockerexec.Capture
	Combined          dockerexec.Capture
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
	databaseInitializerName := name + "-db-init"
	imageName := "vuelta-scan-input:" + strings.TrimPrefix(name, "vuelta-scan-")
	invocation := runlease.Invocation(ctx)
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
	loaderArgs = runlease.AppendLabelArgs(loaderArgs, runlease.OwnerScanner, runlease.ResourceScannerInput, invocation)
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
	if request.Tool == "trivy" && exactDigest.MatchString(request.Image) {
		cacheTag := trivyScannerCacheTag(request.Image)
		if _, err := docker.Run(ctx, dockerexec.Request{
			Args:   []string{"image", "tag", request.Image, cacheTag},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); err != nil {
			return dockerexec.Result{}, fmt.Errorf("retain pinned Trivy scanner image: %w", err)
		}
	}
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args: []string{"cp", "-a", "-", loaderName + ":/"}, Stdin: bytes.NewReader(request.Archive),
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return dockerexec.Result{}, fmt.Errorf("copy scanner input archive: %w", err)
	}
	if request.TrivyDBInitialize {
		if err := initializeTrivyDatabaseVolume(ctx, docker, databaseInitializerName, request); err != nil {
			return dockerexec.Result{}, err
		}
	}
	commitArgs := []string{"commit"}
	for _, label := range runlease.Labels(runlease.OwnerScanner, runlease.ResourceScannerInput, invocation) {
		commitArgs = append(commitArgs, "--change", "LABEL "+label)
	}
	commitArgs = append(commitArgs, loaderName, imageName)
	commitResult, err := docker.Run(ctx, dockerexec.Request{
		// Pausing is Docker's default. Passing the deprecated --pause flag makes
		// recent CLIs write a warning before the image ID and breaks the strict,
		// bounded machine-output contract below.
		Args:   commitArgs,
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
		Args:   createArgs(name, imageID, request, invocation),
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

func trivyScannerCacheTag(image string) string {
	const digestMarker = "@sha256:"
	index := strings.LastIndex(image, digestMarker)
	digest := image[index+len(digestMarker):]
	return "vuelta-scanner-cache:trivy-" + digest
}

func initializeTrivyDatabaseVolume(
	ctx context.Context,
	docker dockerexec.Runner,
	name string,
	request Request,
) error {
	if err := runTrivyDatabaseInitializer(
		ctx,
		docker,
		name,
		request,
		"0:0",
		"CHOWN",
		"/bin/chown",
		"-R",
		"65532:65532",
		"/tmp/trivy/db",
	); err != nil {
		return fmt.Errorf("set Trivy database cache ownership: %w", err)
	}
	if err := runTrivyDatabaseInitializer(
		ctx,
		docker,
		name,
		request,
		"65532:65532",
		"",
		"/bin/chmod",
		"0700",
		"/tmp/trivy/db",
	); err != nil {
		return fmt.Errorf("set Trivy database cache mode: %w", err)
	}
	return nil
}

func runTrivyDatabaseInitializer(
	ctx context.Context,
	docker dockerexec.Runner,
	name string,
	request Request,
	user string,
	capability string,
	entrypoint string,
	command ...string,
) (err error) {
	args := []string{
		"create", "--name", name, "--pull", "never",
		"--network", "none",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--cpus", "0.25",
		"--memory", "32m",
		"--pids-limit", "16",
		"--user", user,
		"--mount", "type=volume,src=" + request.TrivyDBVolume + ",dst=/tmp/trivy/db",
		"--entrypoint", entrypoint,
	}
	args = runlease.AppendLabelArgs(args, runlease.OwnerScanner, runlease.ResourceScannerDB, runlease.Invocation(ctx))
	if capability != "" {
		args = append(args, "--cap-add", capability)
	}
	if request.Platform != "" {
		args = append(args, "--platform", request.Platform)
	}
	args = append(args, request.Image)
	args = append(args, command...)
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args: args, Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return fmt.Errorf("create Trivy database cache initializer: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if _, cleanupErr := docker.Run(cleanupCtx, dockerexec.Request{
			Args: []string{"rm", "-f", name}, Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); cleanupErr != nil {
			err = errors.Join(err, errors.New("remove Trivy database cache initializer"))
		}
	}()
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args: []string{"start", "-a", name}, Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return fmt.Errorf("start Trivy database cache initializer: %w", err)
	}
	return nil
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
	if request.TrivyDBVolume != "" && (request.Tool != "trivy" || !trivyDBVolume.MatchString(request.TrivyDBVolume)) {
		return errors.New("trivy database volume is not a Vuelta-owned cache name")
	}
	if request.TrivyDBInitialize && request.TrivyDBVolume == "" {
		return errors.New("trivy database cache initialization requires a volume")
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

func createArgs(name, image string, request Request, invocation string) []string {
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
	args = runlease.AppendLabelArgs(args, runlease.OwnerScanner, runlease.ResourceScannerFinal, invocation)
	if request.Platform != "" {
		args = append(args, "--platform", request.Platform)
	}
	args = append(args, "--user", user)
	if request.Tool == "trivy" {
		args = append(args,
			"--env", "TRIVY_CACHE_DIR=/tmp/trivy",
			"--env", "TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db",
		)
		if request.TrivyDBVolume != "" {
			mount := "type=volume,src=" + request.TrivyDBVolume + ",dst=/tmp/trivy/db"
			args = append(args, "--mount", mount)
		}
	}
	args = append(args, image)
	return append(args, request.Args...)
}
