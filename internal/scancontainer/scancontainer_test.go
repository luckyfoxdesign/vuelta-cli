package scancontainer

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
)

type fakeDocker struct {
	requests     []dockerexec.Request
	failAt       string
	commitOutput string
	result       dockerexec.Result
}

func (f *fakeDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (f *fakeDocker) Run(ctx context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	if err := ctx.Err(); err != nil && request.Args[0] != "rm" {
		return dockerexec.Result{}, err
	}
	if request.Stdin != nil {
		data, err := io.ReadAll(request.Stdin)
		if err != nil {
			return dockerexec.Result{}, err
		}
		request.Stdin = bytes.NewReader(data)
	}
	f.requests = append(f.requests, request)
	if request.Args[0] == f.failAt {
		return dockerexec.Result{}, errors.New("injected Docker failure")
	}
	if request.Args[0] == "commit" {
		if f.commitOutput != "" {
			return dockerexec.Result{Stdout: []byte(f.commitOutput)}, nil
		}
		return dockerexec.Result{Stdout: []byte("sha256:" + strings.Repeat("b", 64) + "\n")}, nil
	}
	if request.Args[0] == "start" {
		return f.result, nil
	}
	return dockerexec.Result{}, nil
}

func archiveFixture(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	if err := w.WriteHeader(&tar.Header{Name: "project/", Typeflag: tar.TypeDir, Mode: 0o555, Uid: 65532, Gid: 65532}); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"lockfileVersion":3}`)
	if err := w.WriteHeader(&tar.Header{Name: "project/package-lock.json", Typeflag: tar.TypeReg, Mode: 0o444, Size: int64(len(data)), Uid: 65532, Gid: 65532}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func validRequest(t *testing.T) Request {
	t.Helper()
	return Request{
		Image: "registry.example/scanner@sha256:" + strings.Repeat("a", 64), Args: []string{"scan", "/project"},
		Archive: archiveFixture(t), Network: "vuelta-update-egress", Proxy: "http://vuelta-egress-proxy:3128",
		Memory: "1g", Tmpfs: "64m", Combined: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 1024},
	}
}

func TestValidateRequestAcceptsValidatedLocalImageID(t *testing.T) {
	request := validRequest(t)
	request.Image = "sha256:" + strings.Repeat("a", 64)
	if err := validateRequest(request); err != nil {
		t.Fatalf("validated local image ID rejected: %v", err)
	}
}

func TestRunUsesCreateCopyStartRemoveWithoutHostMount(t *testing.T) {
	docker := &fakeDocker{result: dockerexec.Result{Combined: []byte("result")}}
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-test", nil }}
	result, err := runner.Run(context.Background(), validRequest(t))
	if err != nil || string(result.Combined) != "result" {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	commands := make([]string, 0, len(docker.requests))
	for _, request := range docker.requests {
		commands = append(commands, request.Args[0])
	}
	if !reflect.DeepEqual(commands, []string{"create", "cp", "commit", "rm", "create", "start", "rm", "image"}) {
		t.Fatalf("Docker lifecycle = %v", commands)
	}
	loader := strings.Join(docker.requests[0].Args, " ")
	if strings.Contains(loader, "--read-only") || !strings.Contains(loader, "--network none") {
		t.Fatalf("stopped loader has unexpected runtime configuration: %s", loader)
	}
	create := strings.Join(docker.requests[4].Args, " ")
	for _, required := range []string{"--user 65532:65532", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--pull never"} {
		if !strings.Contains(create, required) {
			t.Fatalf("create args missing %q: %s", required, create)
		}
	}
	if strings.Contains(create, "--mount") || strings.Contains(create, " -v ") || strings.Contains(create, "type=bind") {
		t.Fatalf("scanner create unexpectedly exposes a host path: %s", create)
	}
	cpArchive, err := io.ReadAll(docker.requests[1].Stdin)
	if err != nil || !bytes.Equal(cpArchive, validRequest(t).Archive) {
		t.Fatal("docker cp did not receive the exact in-memory archive")
	}
}

func TestRunLabelsEphemeralResourcesWithExactInvocationLease(t *testing.T) {
	docker := &fakeDocker{}
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-labeled", nil }}
	invocation := strings.Repeat("a", 32)
	ctx, err := runlease.WithInvocation(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, validRequest(t)); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 4} {
		args := strings.Join(docker.requests[index].Args, " ")
		for _, label := range []string{
			runlease.OwnerLabel + "=" + runlease.OwnerScanner,
			runlease.ContractLabel + "=" + runlease.ContractValue,
			runlease.InvocationLabel + "=" + invocation,
		} {
			if !strings.Contains(args, "--label "+label) {
				t.Fatalf("create request %d lacks label %q: %s", index, label, args)
			}
		}
	}
	if loader := strings.Join(docker.requests[0].Args, " "); !strings.Contains(loader, runlease.ResourceLabel+"="+runlease.ResourceScannerInput) {
		t.Fatalf("loader resource label missing: %s", loader)
	}
	if scanner := strings.Join(docker.requests[4].Args, " "); !strings.Contains(scanner, runlease.ResourceLabel+"="+runlease.ResourceScannerFinal) {
		t.Fatalf("scanner resource label missing: %s", scanner)
	}
	commit := strings.Join(docker.requests[2].Args, " ")
	if !strings.Contains(commit, "--change LABEL "+runlease.ResourceLabel+"="+runlease.ResourceScannerInput) {
		t.Fatalf("committed image resource label missing: %s", commit)
	}
}

func TestRunUsesProfileDeclaredNonRootUser(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.User = "10001:10002"
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-profile-user", nil }}
	if _, err := runner.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	create := strings.Join(docker.requests[4].Args, " ")
	if !strings.Contains(create, "--user 10001:10002") {
		t.Fatalf("profile user missing from final scanner create: %s", create)
	}
}

func TestRunMountsAllowlistedTrivyDatabaseVolumeWritableForSQLite(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.Tool = "trivy"
	request.TrivyDBVolume = "vuelta-trivy-db-0123456789abcdef"
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-trivy-cache", nil }}
	if _, err := runner.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var create string
	for _, dockerRequest := range docker.requests {
		args := strings.Join(dockerRequest.Args, " ")
		if strings.HasPrefix(args, "create ") && strings.Contains(args, "--read-only") {
			create = args
			break
		}
	}
	if create == "" {
		t.Fatal("final read-only scanner create request is absent")
	}
	for _, required := range []string{
		"TRIVY_CACHE_DIR=/tmp/trivy",
		"TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db",
		"type=volume,src=vuelta-trivy-db-0123456789abcdef,dst=/tmp/trivy/db",
	} {
		if !strings.Contains(create, required) {
			t.Fatalf("Trivy create args missing %q: %s", required, create)
		}
	}
	if strings.Contains(create, "type=bind") {
		t.Fatalf("Trivy database cache exposed a host path: %s", create)
	}
	if strings.Contains(create, "dst=/tmp/trivy/db,readonly") {
		t.Fatalf("Trivy database cache is read-only despite SQLite compatibility writes: %s", create)
	}
	var cacheTag string
	for _, dockerRequest := range docker.requests {
		if len(dockerRequest.Args) == 4 &&
			dockerRequest.Args[0] == "image" &&
			dockerRequest.Args[1] == "tag" {
			cacheTag = strings.Join(dockerRequest.Args, " ")
			break
		}
	}
	wantCacheTag := "image tag " + request.Image + " vuelta-scanner-cache:trivy-" + strings.Repeat("a", 64)
	if cacheTag != wantCacheTag {
		t.Fatalf("Trivy scanner cache tag = %q, want %q", cacheTag, wantCacheTag)
	}
}

func TestTrivyScannerCacheTagTracksExactDigestAndIsNotDangling(t *testing.T) {
	firstDigest := strings.Repeat("a", 64)
	secondDigest := strings.Repeat("b", 64)
	first := trivyScannerCacheTag("aquasec/trivy@sha256:" + firstDigest)
	second := trivyScannerCacheTag("aquasec/trivy@sha256:" + secondDigest)
	if first != "vuelta-scanner-cache:trivy-"+firstDigest {
		t.Fatalf("first cache tag = %q", first)
	}
	if second != "vuelta-scanner-cache:trivy-"+secondDigest || second == first {
		t.Fatalf("changed digest cache tag = %q", second)
	}
	for _, tag := range []string{first, second} {
		if strings.Contains(tag, "<none>") || !strings.Contains(tag, ":trivy-") {
			t.Fatalf("retained scanner image would remain dangling: %q", tag)
		}
	}
}

func TestRunInitializesWritableTrivyDatabaseVolumeWithoutExecutingLoader(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.Tool = "trivy"
	request.TrivyDBVolume = "vuelta-trivy-db-0123456789abcdef"
	request.TrivyDBInitialize = true
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-trivy-acquire", nil }}
	if _, err := runner.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	loader := strings.Join(docker.requests[0].Args, " ")
	if !strings.Contains(loader, "--network none") ||
		strings.Contains(loader, "type=volume,src=vuelta-trivy-db-0123456789abcdef") {
		t.Fatalf("stopped input loader unexpectedly owns database initialization: %s", loader)
	}
	commands := make([]string, 0, len(docker.requests))
	for _, dockerRequest := range docker.requests {
		commands = append(commands, dockerRequest.Args[0])
	}
	if !reflect.DeepEqual(commands, []string{
		"create", "image", "cp", "create", "start", "rm", "create", "start", "rm",
		"commit", "rm", "create", "start", "rm", "image",
	}) {
		t.Fatalf("writable Trivy lifecycle = %v", commands)
	}
}

func TestInitializeTrivyDatabaseVolumeUsesStartedHardenedContainers(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.Tool = "trivy"
	request.TrivyDBVolume = "vuelta-trivy-db-0123456789abcdef"
	if err := initializeTrivyDatabaseVolume(
		context.Background(),
		docker,
		"vuelta-scan-trivy-db-init",
		request,
	); err != nil {
		t.Fatal(err)
	}
	if len(docker.requests) != 6 {
		t.Fatalf("initializer Docker calls = %d, want 6", len(docker.requests))
	}
	chownCreate := strings.Join(docker.requests[0].Args, " ")
	for _, required := range []string{
		"--pull never",
		"--network none",
		"--read-only",
		"--security-opt no-new-privileges",
		"--cap-drop ALL",
		"--cap-add CHOWN",
		"--user 0:0",
		"type=volume,src=vuelta-trivy-db-0123456789abcdef,dst=/tmp/trivy/db",
		"--entrypoint /bin/chown",
		"-R 65532:65532 /tmp/trivy/db",
	} {
		if !strings.Contains(chownCreate, required) {
			t.Fatalf("ownership initializer create args missing %q: %s", required, chownCreate)
		}
	}
	if strings.Contains(chownCreate, "type=bind") {
		t.Fatalf("ownership initializer exposed a host path: %s", chownCreate)
	}
	if got := strings.Join(docker.requests[1].Args, " "); got != "start -a vuelta-scan-trivy-db-init" {
		t.Fatalf("ownership initializer start = %q", got)
	}
	if got := strings.Join(docker.requests[2].Args, " "); got != "rm -f vuelta-scan-trivy-db-init" {
		t.Fatalf("ownership initializer cleanup = %q", got)
	}
	chmodCreate := strings.Join(docker.requests[3].Args, " ")
	for _, required := range []string{
		"--cap-drop ALL",
		"--user 65532:65532",
		"--entrypoint /bin/chmod",
		"0700 /tmp/trivy/db",
	} {
		if !strings.Contains(chmodCreate, required) {
			t.Fatalf("mode initializer create args missing %q: %s", required, chmodCreate)
		}
	}
	if strings.Contains(chmodCreate, "--cap-add") {
		t.Fatalf("mode initializer unexpectedly gained a capability: %s", chmodCreate)
	}
	if got := strings.Join(docker.requests[4].Args, " "); got != "start -a vuelta-scan-trivy-db-init" {
		t.Fatalf("mode initializer start = %q", got)
	}
	if got := strings.Join(docker.requests[5].Args, " "); got != "rm -f vuelta-scan-trivy-db-init" {
		t.Fatalf("mode initializer cleanup = %q", got)
	}
}

func TestRunRejectsForeignTrivyDatabaseVolumeBeforeDocker(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.Tool = "trivy"
	request.TrivyDBVolume = "project-controlled-cache"
	if _, err := (Runner{Docker: docker}).Run(context.Background(), request); err == nil {
		t.Fatal("foreign Trivy database volume was accepted")
	}
	if len(docker.requests) != 0 {
		t.Fatalf("Docker was called for a foreign cache: %#v", docker.requests)
	}
}

func TestRunUsesAllowlistedProfilePlatformForLoaderAndScanner(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.Platform = "linux/arm64"
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-profile-platform", nil }}
	if _, err := runner.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 4} {
		args := strings.Join(docker.requests[index].Args, " ")
		if !strings.Contains(args, "--platform linux/arm64") {
			t.Fatalf("profile platform missing from create request %d: %s", index, args)
		}
	}
}

func TestRunRejectsNonAllowlistedProfilePlatformBeforeDocker(t *testing.T) {
	docker := &fakeDocker{}
	request := validRequest(t)
	request.Platform = "linux/s390x"
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-invalid-platform", nil }}
	_, err := runner.Run(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "scanner platform") {
		t.Fatalf("Run error = %v", err)
	}
	if len(docker.requests) != 0 {
		t.Fatalf("Docker was called for invalid platform: %#v", docker.requests)
	}
}

func TestRunCleansUpAfterCopyFailure(t *testing.T) {
	docker := &fakeDocker{failAt: "cp"}
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-test", nil }}
	_, err := runner.Run(context.Background(), validRequest(t))
	if err == nil || !strings.Contains(err.Error(), "copy scanner input") {
		t.Fatalf("Run error = %v", err)
	}
	commands := []string{}
	for _, request := range docker.requests {
		commands = append(commands, request.Args[0])
	}
	if !reflect.DeepEqual(commands, []string{"create", "cp", "rm"}) {
		t.Fatalf("Docker lifecycle after copy failure = %v", commands)
	}
}

func TestRunRejectsInvalidCommittedImageIDAndCleansOwnedResources(t *testing.T) {
	docker := &fakeDocker{commitOutput: "unexpected-image-output\n"}
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-test", nil }}
	_, err := runner.Run(context.Background(), validRequest(t))
	if err == nil || !strings.Contains(err.Error(), "invalid ID") {
		t.Fatalf("Run error = %v", err)
	}
	commands := []string{}
	for _, request := range docker.requests {
		commands = append(commands, request.Args[0])
	}
	if !reflect.DeepEqual(commands, []string{"create", "cp", "commit", "rm", "image"}) {
		t.Fatalf("Docker lifecycle after invalid commit output = %v", commands)
	}
}

func TestRunUsesIndependentCleanupAfterCancellation(t *testing.T) {
	docker := &fakeDocker{}
	docker.failAt = "start"
	runner := Runner{Docker: docker, NewName: func() (string, error) { return "vuelta-scan-test", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runner.Run(ctx, validRequest(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want canceled", err)
	}
	if len(docker.requests) != 0 {
		t.Fatalf("canceled create unexpectedly removed an unowned resource: %#v", docker.requests)
	}
}

func TestRunRejectsArchiveTraversalBeforeDocker(t *testing.T) {
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	if err := w.WriteHeader(&tar.Header{Name: "../outside", Typeflag: tar.TypeReg, Mode: 0o444, Uid: 65532, Gid: 65532}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	request := validRequest(t)
	request.Archive = buffer.Bytes()
	docker := &fakeDocker{}
	_, err := (Runner{Docker: docker}).Run(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "escapes") || len(docker.requests) != 0 {
		t.Fatalf("Run error = %v, Docker calls = %d", err, len(docker.requests))
	}
}
