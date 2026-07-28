package egress

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
)

const testImageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type lifecycleDocker struct {
	networkExists      bool
	networkName        string
	networkAttachments []string
	networkContract    string
	foreignNetwork     bool
	containerExists    bool
	containerName      string
	containerContract  string
	foreign            bool
	stale              bool
	running            bool
	healthy            bool
	neverHealthy       bool
	scannerInvocations map[string]string
	scannerContainerID string
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
		requested := args[len(args)-1]
		if !d.networkExists || (d.networkName != "" && d.networkName != requested) {
			return dockerexec.Result{}, errors.New("missing network")
		}
		if len(args) > 3 && strings.Contains(args[3], "range .Containers") {
			return dockerexec.Result{Stdout: []byte(strings.Join(d.networkAttachments, "\n"))}, nil
		}
		owner := ownerValue
		if d.foreignNetwork {
			owner = "another-application"
		}
		contract := d.networkContract
		if contract == "" {
			contract = networkContractValue
		}
		return dockerexec.Result{Stdout: []byte(`{"name":"` + requested + `","internal":true,"owner":"` + owner + `","contract":"` + contract + `","container_count":0}`)}, nil
	case "network create":
		d.networkExists, d.networkName, d.foreignNetwork = true, args[len(args)-1], false
		d.networkAttachments = nil
		return dockerexec.Result{Stdout: []byte("network-id")}, nil
	case "network connect":
		return dockerexec.Result{}, nil
	case "network rm":
		d.networkExists = false
		return dockerexec.Result{}, nil
	case "container inspect":
		requested := args[len(args)-1]
		if invocation, ok := d.scannerInvocations[requested]; ok {
			output := `{"owner":"` + runlease.OwnerScanner + `","lifecycle_contract":"` + runlease.ContractValue +
				`","invocation":"` + invocation + `","resource":"` + runlease.ResourceScannerFinal + `"}`
			return dockerexec.Result{Stdout: []byte(output)}, nil
		}
		if !d.containerExists || (d.containerName != "" && d.containerName != requested) {
			return dockerexec.Result{}, errors.New("missing container")
		}
		owner := ownerValue
		if d.foreign {
			owner = "another-application"
		}
		contract := "contract"
		if d.containerContract != "" {
			contract = d.containerContract
		}
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
	case "container ls":
		joined := strings.Join(args, " ")
		if strings.Contains(joined, runlease.ResourceLabel+"="+runlease.ResourceScannerFinal) &&
			len(d.scannerInvocations) > 0 {
			return dockerexec.Result{Stdout: []byte(d.scannerContainerID + "\n")}, nil
		}
		return dockerexec.Result{}, nil
	case "container rm":
		if len(args) > 0 && args[len(args)-1] == d.scannerContainerID {
			d.scannerInvocations = nil
			filtered := d.networkAttachments[:0]
			for _, attachment := range d.networkAttachments {
				if !strings.HasPrefix(attachment, "vuelta-scan-") {
					filtered = append(filtered, attachment)
				}
			}
			d.networkAttachments = filtered
			return dockerexec.Result{}, nil
		}
		d.containerExists, d.running, d.healthy, d.stale = false, false, false, false
		return dockerexec.Result{}, nil
	case "container create":
		d.containerExists, d.containerName, d.foreign = true, optionValue(args, "--name"), false
		d.containerContract = labelValue(args, contractLabel)
		return dockerexec.Result{Stdout: []byte("container-id")}, nil
	case "container start":
		d.running, d.healthy = true, !d.neverHealthy
		return dockerexec.Result{Stdout: []byte("vuelta-egress-proxy")}, nil
	case "image inspect":
		return dockerexec.Result{Stdout: []byte(`{"id":"` + testImageID + `","os":"linux","architecture":"amd64","user":"65532:65532","contract":"` + assetContract() + `"}`)}, nil
	case "image ls", "network ls":
		return dockerexec.Result{}, nil
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

func optionValue(args []string, option string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == option {
			return args[index+1]
		}
	}
	return ""
}

func labelValue(args []string, label string) string {
	prefix := label + "="
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--label" && strings.HasPrefix(args[index+1], prefix) {
			return strings.TrimPrefix(args[index+1], prefix)
		}
	}
	return ""
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

func TestSessionAvoidsForeignConfiguredResourcesWithoutMutatingThem(t *testing.T) {
	docker := &lifecycleDocker{
		networkExists: true, networkName: "vuelta-update-egress", foreignNetwork: true,
		containerExists: true, containerName: "vuelta-egress-proxy", containerContract: assetContract(),
		foreign: true, running: true, healthy: true,
	}
	session := NewSession(testEgressConfig(), docker)
	network, proxy, err := session.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve with foreign configured resources: %v", err)
	}
	if !strings.HasPrefix(network, "vuelta-managed-egress-") ||
		!strings.HasPrefix(proxy, "http://vuelta-managed-egress-proxy-") {
		t.Fatalf("fallback network/proxy = %q, %q", network, proxy)
	}
	if session.Notice() == "" {
		t.Fatal("fallback session omitted its user-facing notice")
	}
	if commandTargeted(docker.calls, "network", "rm", "vuelta-update-egress") ||
		commandTargeted(docker.calls, "container", "rm", "vuelta-egress-proxy") {
		t.Fatalf("foreign resources were targeted: %v", docker.calls)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("close fallback session: %v", err)
	}
	if commandTargeted(docker.calls, "network", "rm", "vuelta-update-egress") ||
		commandTargeted(docker.calls, "container", "rm", "vuelta-egress-proxy") {
		t.Fatalf("foreign resources were targeted during cleanup: %v", docker.calls)
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

func TestPersistentSessionKeepsLifecycleLockUntilClose(t *testing.T) {
	docker := &lifecycleDocker{
		networkExists: true, networkAttachments: []string{"vuelta-egress-proxy"},
		containerExists: true, containerContract: assetContract(), running: true, healthy: true,
	}
	cfg := testEgressConfig()
	cfg.Persistent = true
	session := NewSession(cfg, docker)
	if _, _, err := session.Resolve(context.Background()); err != nil {
		t.Fatalf("persistent resolve: %v", err)
	}
	if session.lock == nil {
		t.Fatal("persistent session released its lifecycle lock before Close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireLifecycleLock(ctx, cfg.Network); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent lock error = %v, want deadline", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("close persistent session: %v", err)
	}
	if session.lock != nil {
		t.Fatal("persistent session retained its lifecycle lock after Close")
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

func TestInvocationSessionLabelsTemporaryEgressButPersistentSessionDoesNot(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	ctx, err := runlease.WithInvocation(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	temporaryDocker := &lifecycleDocker{}
	temporary := NewSession(testEgressConfig(), temporaryDocker)
	if _, _, err := temporary.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range [][]string{{"network", "create"}, {"container", "create"}} {
		call := findCommand(temporaryDocker.calls, prefix...)
		if call == nil {
			t.Fatalf("missing create call %v: %v", prefix, temporaryDocker.calls)
		}
		for _, label := range []string{
			runlease.ContractLabel + "=" + runlease.ContractValue,
			runlease.InvocationLabel + "=" + invocation,
		} {
			if !containsPair(call, "--label", label) {
				t.Fatalf("temporary create call lacks %q: %v", label, call)
			}
		}
	}
	if err := temporary.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	persistentDocker := &lifecycleDocker{}
	cfg := testEgressConfig()
	cfg.Persistent = true
	persistent := NewSession(cfg, persistentDocker)
	if _, _, err := persistent.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range [][]string{{"network", "create"}, {"container", "create"}} {
		call := findCommand(persistentDocker.calls, prefix...)
		if call == nil {
			t.Fatalf("missing persistent create call %v: %v", prefix, persistentDocker.calls)
		}
		if containsValue(call, runlease.InvocationLabel+"="+invocation) {
			t.Fatalf("persistent resource inherited invocation label: %v", call)
		}
	}
	if err := persistent.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOrphanRecoveryRemovesLabeledScannerBeforeNameCollisionCheck(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	scannerID := strings.Repeat("b", 64)
	cfg := testEgressConfig()
	docker := &lifecycleDocker{
		networkExists:      true,
		networkName:        cfg.Network,
		networkAttachments: []string{cfg.ProxyContainer, "vuelta-scan-orphan"},
		containerExists:    true,
		containerName:      cfg.ProxyContainer,
		containerContract:  assetContract(),
		running:            true,
		healthy:            true,
		scannerInvocations: map[string]string{"vuelta-scan-orphan": invocation},
		scannerContainerID: scannerID,
	}
	if err := reapStaleManagedResources(context.Background(), docker, cfg); err != nil {
		t.Fatal(err)
	}
	if len(docker.scannerInvocations) != 0 {
		t.Fatalf("orphan scanner was not removed: %v", docker.calls)
	}
	if !docker.networkExists || !docker.containerExists {
		t.Fatalf("persistent egress was removed: network=%v proxy=%v", docker.networkExists, docker.containerExists)
	}
	resolved, err := collisionFreeConfig(context.Background(), docker, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != cfg {
		t.Fatalf("subsequent scan fell back after recovery: got %#v want %#v", resolved, cfg)
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

func commandTargeted(calls [][]string, kind, action, target string) bool {
	for _, call := range calls {
		if len(call) >= 3 && call[0] == kind && call[1] == action && call[len(call)-1] == target {
			return true
		}
	}
	return false
}

func findCommand(calls [][]string, prefix ...string) []string {
	for _, call := range calls {
		if len(call) < len(prefix) {
			continue
		}
		match := true
		for index := range prefix {
			match = match && call[index] == prefix[index]
		}
		if match {
			return call
		}
	}
	return nil
}

func containsPair(values []string, first, second string) bool {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == first && values[index+1] == second {
			return true
		}
	}
	return false
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
