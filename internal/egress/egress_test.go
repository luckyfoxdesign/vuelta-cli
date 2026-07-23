package egress

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

const testImageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type lifecycleDocker struct {
	networkExists      bool
	networkAttachments []string
	networkContract    string
	containerExists    bool
	foreign            bool
	stale              bool
	running            bool
	healthy            bool
	neverHealthy       bool
	calls              [][]string
}

func (d *lifecycleDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *lifecycleDocker) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	d.calls = append(d.calls, append([]string(nil), request.Args...))
	args := request.Args
	if len(args) < 2 {
		return dockerexec.Result{}, errors.New("unexpected command")
	}
	switch strings.Join(args[:2], " ") {
	case "network inspect":
		if !d.networkExists {
			return dockerexec.Result{}, errors.New("missing network")
		}
		if len(args) > 3 && strings.Contains(args[3], "range .Containers") {
			return dockerexec.Result{Stdout: []byte(strings.Join(d.networkAttachments, "\n"))}, nil
		}
		contract := d.networkContract
		if contract == "" {
			contract = networkContractValue
		}
		return dockerexec.Result{Stdout: []byte(`{"name":"vuelta-update-egress","internal":true,"owner":"managed-egress","contract":"` + contract + `","container_count":0}`)}, nil
	case "network create":
		d.networkExists = true
		return dockerexec.Result{Stdout: []byte("network-id")}, nil
	case "network connect":
		return dockerexec.Result{}, nil
	case "network rm":
		d.networkExists = false
		return dockerexec.Result{}, nil
	case "container inspect":
		if !d.containerExists {
			return dockerexec.Result{}, errors.New("missing container")
		}
		owner := ownerValue
		if d.foreign {
			owner = "another-application"
		}
		contract := "contract"
		image := testImageID
		networkCount := 2
		if d.stale {
			contract = "old-contract"
			image = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			networkCount = 3
		}
		health := "starting"
		if d.healthy {
			health = "healthy"
		}
		output := `{"id":"container-id","image":"` + image + `","running":` + boolJSON(d.running) + `,"health":"` + health + `","owner":"` + owner + `","contract":"` + contract + `","read_only":true,"user":"65532:65532","network_mode":"bridge","network_count":` + intJSON(networkCount) + `,"on_internal":true,"on_bridge":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"memory":67108864,"pids_limit":64,"nano_cpus":500000000}`
		return dockerexec.Result{Stdout: []byte(output)}, nil
	case "container rm":
		d.containerExists, d.running, d.healthy, d.stale = false, false, false, false
		return dockerexec.Result{}, nil
	case "container create":
		d.containerExists = true
		return dockerexec.Result{Stdout: []byte("container-id")}, nil
	case "container start":
		d.running, d.healthy = true, !d.neverHealthy
		return dockerexec.Result{Stdout: []byte("vuelta-egress-proxy")}, nil
	case "image inspect":
		return dockerexec.Result{Stdout: []byte(`{"id":"` + testImageID + `","os":"linux","architecture":"amd64","user":"65532:65532","contract":"` + assetContract() + `"}`)}, nil
	default:
		return dockerexec.Result{}, errors.New("unexpected command: " + strings.Join(args, " "))
	}
}

func boolJSON(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func intJSON(value int) string {
	if value == 2 {
		return "2"
	}
	return "3"
}

func testEgressConfig() config.EgressConfig {
	return config.EgressConfig{Network: "vuelta-update-egress", ProxyContainer: "vuelta-egress-proxy", ProxyURL: "http://vuelta-egress-proxy:3128"}
}

func TestEnsureProxyReusesHealthyOwnedContainer(t *testing.T) {
	docker := &lifecycleDocker{containerExists: true, running: true, healthy: true}
	created, err := ensureProxy(context.Background(), docker, testEgressConfig(), testImageID, "contract")
	if err != nil || created {
		t.Fatalf("ensureProxy = created %v, error %v", created, err)
	}
	if commandSeen(docker.calls, "container", "rm") || commandSeen(docker.calls, "container", "create") {
		t.Fatalf("healthy proxy was replaced: %v", docker.calls)
	}
}

func TestEnsureProxyRejectsForeignNameCollision(t *testing.T) {
	docker := &lifecycleDocker{containerExists: true, foreign: true, running: true, healthy: true}
	_, err := ensureProxy(context.Background(), docker, testEgressConfig(), testImageID, "contract")
	if err == nil || !strings.Contains(err.Error(), "owned by another application") {
		t.Fatalf("collision error = %v", err)
	}
	if commandSeen(docker.calls, "container", "rm") {
		t.Fatalf("foreign container was targeted: %v", docker.calls)
	}
}

func TestEnsureProxyReplacesOnlyStaleOwnedContainer(t *testing.T) {
	docker := &lifecycleDocker{containerExists: true, stale: true, running: true}
	created, err := ensureProxy(context.Background(), docker, testEgressConfig(), testImageID, "contract")
	if err != nil || !created {
		t.Fatalf("ensureProxy = created %v, error %v", created, err)
	}
	for _, wanted := range [][]string{{"container", "rm"}, {"container", "create"}, {"network", "connect"}, {"container", "start"}} {
		if !commandSeen(docker.calls, wanted...) {
			t.Fatalf("missing command %v in %v", wanted, docker.calls)
		}
	}
}

func TestEnsureNetworkRejectsForeignOrMismatchedNetwork(t *testing.T) {
	docker := &lifecycleDocker{networkExists: true}
	if _, err := ensureNetwork(context.Background(), docker, "vuelta-update-egress", "vuelta-egress-proxy", "different-contract"); err == nil {
		t.Fatal("mismatched network succeeded")
	}
	if commandSeen(docker.calls, "network", "rm") {
		t.Fatalf("existing network was targeted: %v", docker.calls)
	}
}

func TestEnsureNetworkRejectsUnexpectedAttachmentWithoutRemovingIt(t *testing.T) {
	docker := &lifecycleDocker{networkExists: true, networkAttachments: []string{"foreign-container"}, networkContract: "contract"}
	if _, err := ensureNetwork(context.Background(), docker, "vuelta-update-egress", "vuelta-egress-proxy", "contract"); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("attachment error = %v", err)
	}
	if commandSeen(docker.calls, "network", "rm") {
		t.Fatalf("network with foreign attachment was targeted: %v", docker.calls)
	}
}

func TestSessionReverifiesHealthAndAttachmentsBetweenStages(t *testing.T) {
	docker := &lifecycleDocker{
		networkExists: true, networkAttachments: []string{"vuelta-egress-proxy"},
		containerExists: true, running: true, healthy: true,
	}
	session := &Session{
		cfg: testEgressConfig(), docker: docker, ensured: true,
		imageID: testImageID, contract: "contract",
	}
	if _, _, err := session.Resolve(context.Background()); err != nil {
		t.Fatalf("healthy second-stage resolve: %v", err)
	}
	docker.healthy = false
	if _, _, err := session.Resolve(context.Background()); err == nil || !strings.Contains(err.Error(), "proxy verification") {
		t.Fatalf("drifted second-stage resolve error = %v", err)
	}
}

func TestProxyCreationCancellationCleansOwnedContainer(t *testing.T) {
	docker := &lifecycleDocker{neverHealthy: true}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_, err := createProxy(ctx, docker, testEgressConfig(), testImageID, "contract")
	if !errors.Is(err, context.Canceled) && (err == nil || !strings.Contains(err.Error(), "did not become healthy")) {
		t.Fatalf("createProxy cancellation error = %v", err)
	}
	if docker.containerExists || !commandSeen(docker.calls, "container", "rm") {
		t.Fatalf("cancelled proxy was not cleaned: exists=%v calls=%v", docker.containerExists, docker.calls)
	}
}

func TestLifecycleLockSerializesConcurrentInvocations(t *testing.T) {
	first, err := acquireLifecycleLock(context.Background(), "vuelta-lock-test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireLifecycleLock(ctx, "vuelta-lock-test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock error = %v, want deadline", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireLifecycleLock(context.Background(), "vuelta-lock-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCleanupTargetsOnlyResourcesItCreated(t *testing.T) {
	docker := &lifecycleDocker{networkExists: true, containerExists: true, running: true, healthy: true}
	session := &Session{cfg: testEgressConfig(), docker: docker, networkCreated: true, containerCreated: true, ensured: true}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !commandSeen(docker.calls, "container", "rm") || !commandSeen(docker.calls, "network", "rm") {
		t.Fatalf("cleanup calls = %v", docker.calls)
	}
	docker.calls = nil
	session = &Session{cfg: testEgressConfig(), docker: docker, ensured: true}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(docker.calls) != 0 {
		t.Fatalf("reused resources were targeted: %v", docker.calls)
	}
}

func TestEmbeddedAssetContractIsDigestPinnedAndStable(t *testing.T) {
	contract := assetContract()
	if len(contract) != 64 || !strings.Contains(proxyDockerfile, "@sha256:") || strings.Contains(proxyDockerfile, "COPY egress/") {
		t.Fatalf("asset contract %q or Dockerfile is not self-contained and pinned", contract)
	}
	docker := &lifecycleDocker{}
	imageID, gotContract, err := ensureAsset(context.Background(), docker)
	if err != nil || imageID != testImageID || gotContract != contract {
		t.Fatalf("ensureAsset = %q, %q, %v", imageID, gotContract, err)
	}
}

func commandSeen(calls [][]string, prefix ...string) bool {
	for _, call := range calls {
		if len(call) < len(prefix) {
			continue
		}
		match := true
		for index := range prefix {
			match = match && call[index] == prefix[index]
		}
		if match {
			return true
		}
	}
	return false
}
