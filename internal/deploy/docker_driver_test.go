package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/history"
)

type recordingDockerRunner struct {
	requests []dockerexec.Request
	run      func(dockerexec.Request) (dockerexec.Result, error)
}

func (r *recordingDockerRunner) Path() (string, error) { return "/usr/bin/docker", nil }
func (r *recordingDockerRunner) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	r.requests = append(r.requests, request)
	return r.run(request)
}

func TestDockerDriverPullVerifiesOCIIdentityWithoutCredentialArgv(t *testing.T) {
	runner := &recordingDockerRunner{}
	runner.run = func(request dockerexec.Request) (dockerexec.Result, error) {
		if slices.Contains(request.Args, "inspect") {
			return dockerexec.Result{Stdout: []byte(`{
				"repo_digests":["ghcr.io/example/api@` + candidateDigest + `"],
				"labels":{
					"org.opencontainers.image.source":"https://github.com/example/api",
					"org.opencontainers.image.revision":"` + runtimeCommit + `"
				}
			}`)}, nil
		}
		return dockerexec.Result{}, nil
	}
	driver := newDockerDriverFixture(t, runner)
	digest, err := driver.PullExact(context.Background(), Contract{
		Project: "api", Repository: "example/api",
	}, history.DeploymentRelease{
		SourceCommit: runtimeCommit, ImageRepository: "ghcr.io/example/api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if digest != candidateDigest {
		t.Fatalf("digest = %q", digest)
	}
	for _, request := range runner.requests {
		joined := strings.Join(request.Args, " ")
		if strings.Contains(joined, "registry-secret") {
			t.Fatalf("credential escaped into argv: %#v", request.Args)
		}
		for _, value := range request.Env {
			if strings.Contains(value, "registry-secret") {
				t.Fatal("credential escaped into child environment")
			}
		}
	}
	if len(runner.requests) == 0 || runner.requests[0].Stdin == nil {
		t.Fatal("registry credential was not supplied through bounded stdin")
	}
}

func TestDockerDriverWritesOverlayOutsideProjectAndUsesComposeRun(t *testing.T) {
	root := t.TempDir()
	composePath := filepath.Join(root, "compose.yml")
	original := []byte("services:\n  api:\n    build: .\n")
	if err := os.WriteFile(composePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingDockerRunner{run: func(dockerexec.Request) (dockerexec.Result, error) {
		return dockerexec.Result{Stdout: []byte("container-id")}, nil
	}}
	driver := newDockerDriverFixture(t, runner)
	candidate, err := driver.StartCandidate(context.Background(), Contract{
		Project: "api", Root: root, ComposeFiles: []string{"compose.yml"},
		TrafficService: "api",
	}, history.DeploymentRelease{
		ImageRepository: "ghcr.io/example/api", CandidateDigest: candidateDigest,
	}, "green")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Container != "vuelta-api-green-api" {
		t.Fatalf("candidate = %#v", candidate)
	}
	after, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("managed project Compose file was modified")
	}
	request := runner.requests[len(runner.requests)-1]
	if !slices.Contains(request.Args, "run") || !slices.Contains(request.Args, "--no-deps") ||
		request.Env["VUELTA_IMAGE"] != "ghcr.io/example/api@"+candidateDigest {
		t.Fatalf("compose request = %#v env=%#v", request.Args, request.Env)
	}
	if slices.Contains(request.Args, ".env") {
		t.Fatal("Vuelta attempted to read or pass a project env file")
	}
}

func TestTraefikGatewayLabelsCloneOnlyReviewedRoutingFields(t *testing.T) {
	labels := traefikGatewayLabels(Contract{
		Project: "api", ExternalNetworks: []string{"traefik-public"}, InternalPort: 8000,
	}, map[string]string{
		"traefik.enable":                            "true",
		"traefik.http.routers.api.rule":             "Host(`api.example.com`)",
		"traefik.http.routers.api.entrypoints":      "websecure",
		"traefik.http.routers.api.tls.certresolver": "letsencrypt",
		"traefik.http.middlewares.evil.plugin.foo":  "unreviewed",
		"unrelated.secret":                          "must-not-copy",
	})
	if labels["traefik.http.routers.vuelta-api.rule"] != "Host(`api.example.com`)" ||
		labels["traefik.http.services.vuelta-api.loadbalancer.server.port"] != "8000" {
		t.Fatalf("labels = %#v", labels)
	}
	if _, ok := labels["unrelated.secret"]; ok {
		t.Fatal("unrelated label was copied")
	}
	if _, ok := labels["traefik.http.middlewares.evil.plugin.foo"]; ok {
		t.Fatal("unreviewed middleware definition was copied")
	}
}

func TestDockerDriverSwitchTrafficStartsOwnedTraefikGateway(t *testing.T) {
	runner := &recordingDockerRunner{}
	runner.run = func(request dockerexec.Request) (dockerexec.Result, error) {
		if slices.Equal(request.Args[:min(2, len(request.Args))], []string{"container", "inspect"}) {
			return dockerexec.Result{}, errors.New("gateway does not exist")
		}
		return dockerexec.Result{}, nil
	}
	driver := newDockerDriverFixture(t, runner)
	contract := Contract{
		Project: "api", TrafficService: "api", InternalPort: 8000,
		HealthPath: "/health", ExternalNetworks: []string{"traefik-public"},
	}
	current := RunningSlot{Labels: map[string]string{
		"traefik.enable":                        "true",
		"traefik.http.routers.api.rule":         "Host(`api.example.com`)",
		"traefik.http.routers.api.entrypoints":  "websecure",
		"traefik.http.routers.api.tls":          "true",
		"traefik.http.routers.api.middlewares":  "secure@docker",
		"unrelated.project.configuration.value": "ignored",
	}}
	if err := driver.SwitchTraffic(context.Background(), contract, current, CandidateSlot{
		Name: "api", Slot: "green", Digest: candidateDigest, Container: "vuelta-api-green-api",
	}); err != nil {
		t.Fatal(err)
	}
	var runArgs []string
	for _, request := range runner.requests {
		if len(request.Args) > 0 && request.Args[0] == "run" {
			runArgs = request.Args
			break
		}
	}
	if len(runArgs) == 0 {
		t.Fatalf("Docker requests = %#v", runner.requests)
	}
	joined := strings.Join(runArgs, "\n")
	for _, expected := range []string{
		ownerLabel + "=true",
		"traefik.http.routers.vuelta-api.rule=Host(`api.example.com`)",
		"traefik.http.routers.vuelta-api.priority=2147483000",
		"traefik.http.services.vuelta-api.loadbalancer.server.port=8000",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("gateway run args missing %q: %#v", expected, runArgs)
		}
	}
	if slices.Contains(runArgs, "--network-alias") ||
		strings.Contains(joined, "unrelated.project.configuration.value") {
		t.Fatalf("Traefik gateway escaped the reviewed label contract: %#v", runArgs)
	}
}

func TestDockerDriverPreflightRejectsLowResources(t *testing.T) {
	runner := &recordingDockerRunner{run: func(dockerexec.Request) (dockerexec.Result, error) {
		return dockerexec.Result{}, nil
	}}
	stateDir := filepath.Join(t.TempDir(), "state")
	driver, err := NewDockerDriver(DockerDriverOptions{
		Runner:          runner,
		StateDir:        stateDir,
		GatewayImage:    "ghcr.io/example/vuelta-gateway@" + previousDigest,
		RegistryUser:    "example",
		RegistryToken:   "registry-secret",
		MinFreeMemoryMB: 512,
		MinFreeDiskMB:   1024,
		ResourceProbe: func(string) (HostResources, error) {
			return HostResources{FreeMemoryMB: 256, FreeDiskMB: 2048}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	contract := Contract{
		Project: "api", Services: []Service{{Name: "api"}},
		TrafficService: "api", InternalPort: 8080, HealthPath: "/health",
		StableUpstream: "api", ExternalNetworks: []string{"proxy"},
	}
	if err := driver.Preflight(context.Background(), contract); err == nil ||
		!strings.Contains(err.Error(), "memory available") {
		t.Fatalf("Preflight() error = %v, want bounded low-memory failure", err)
	}
}

func newDockerDriverFixture(t *testing.T, runner dockerexec.Runner) *DockerDriver {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	driver, err := NewDockerDriver(DockerDriverOptions{
		Runner: runner, StateDir: stateDir,
		GatewayImage: "ghcr.io/example/vuelta-gateway@" + previousDigest,
		RegistryUser: "example", RegistryToken: "registry-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}
