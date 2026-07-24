// Package egress owns the fail-closed Docker network and registry proxy used
// by networked scanner stages.
package egress

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egressproxy"
)

const (
	assetContractVersion = 1
	networkContractValue = "1"
	ownerLabel           = "com.luckyfoxdesign.vuelta.owner"
	contractLabel        = "com.luckyfoxdesign.vuelta.contract"
	ownerValue           = "managed-egress"
	proxyUser            = "65532:65532"
	proxyBuildTimeout    = 20 * time.Minute
	proxyHealthTimeout   = 45 * time.Second
	proxyCleanupTimeout  = 30 * time.Second
)

const proxyDockerfile = `FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod ./go.mod
COPY main.go ./main.go
COPY egressproxy/proxy.go ./egressproxy/proxy.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /egress-proxy ./main.go

FROM scratch
COPY --from=build /egress-proxy /egress-proxy
USER 65532:65532
EXPOSE 3128
HEALTHCHECK --interval=2s --timeout=2s --retries=15 CMD ["/egress-proxy", "--healthcheck"]
ENTRYPOINT ["/egress-proxy"]
`

const allowRules = "https://pypi.org:443,https://files.pythonhosted.org:443," +
	"https://registry.npmjs.org:443,https://registry.yarnpkg.com:443," +
	"https://registry.bun.sh:443,https://github.com:443," +
	"https://objects.githubusercontent.com:443,https://ghcr.io:443," +
	"https://pkg-containers.githubusercontent.com:443,https://api.osv.dev:443," +
	"https://registry-1.docker.io:443,https://auth.docker.io:443," +
	"https://production.cloudflare.docker.com:443"

// ErrPolicyUnavailable means the required registry allowlist environment
// could not be prepared or verified. Callers must never fall back to Docker's
// default bridge network.
var ErrPolicyUnavailable = errors.New("egress policy unavailable")

// StageError identifies the managed egress preparation stage without exposing
// Docker argv or unbounded command output.
type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string { return fmt.Sprintf("egress %s failed: %v", e.Stage, e.Err) }
func (e *StageError) Unwrap() error { return errors.Join(ErrPolicyUnavailable, e.Err) }

type sessionContextKey struct{}

// Session owns at most one invocation's egress resources. Ensure is lazy and
// safe for repeated stage calls; Close removes only resources this session
// created unless persistence is explicitly configured.
type Session struct {
	requested config.EgressConfig
	cfg       config.EgressConfig
	docker    dockerexec.Runner

	mu               sync.Mutex
	lock             lifecycleLock
	fallbackUsed     bool
	ensured          bool
	networkCreated   bool
	containerCreated bool
	imageID          string
	contract         string
}

// NewSession creates a lazy managed egress session.
func NewSession(cfg config.EgressConfig, docker dockerexec.Runner) *Session {
	return &Session{requested: cfg, cfg: cfg, docker: docker}
}

// WithSession attaches one invocation-scoped session to stage contexts.
func WithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// Resolve ensures the configured policy using the process-wide Docker boundary.
func Resolve(ctx context.Context, cfg config.EgressConfig) (network, proxyURL string, err error) {
	return ResolveWith(ctx, cfg, dockerexec.Default())
}

// ResolveWith ensures and verifies the managed network/proxy. CLI entrypoints
// attach a Session so all stages reuse one lifecycle. Non-CLI callers get a
// persistent one-shot session and therefore never leak invocation cleanup
// responsibility across an API boundary.
func ResolveWith(ctx context.Context, cfg config.EgressConfig, docker dockerexec.Runner) (network, proxyURL string, err error) {
	if session, ok := ctx.Value(sessionContextKey{}).(*Session); ok && session != nil {
		if session.requested != cfg {
			return "", "", &StageError{Stage: "configuration", Err: errors.New("stage egress configuration differs from invocation configuration")}
		}
		return session.Resolve(ctx)
	}
	standalone := NewSession(cfg, docker)
	standalone.cfg.Persistent = true
	network, proxyURL, err = standalone.Resolve(ctx)
	closeErr := standalone.Close(context.Background())
	return network, proxyURL, errors.Join(err, closeErr)
}

// Resolve prepares the policy once and returns the only network and proxy URL
// scanner containers may use.
func (s *Session) Resolve(ctx context.Context) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ensured {
		network, err := inspectNetwork(ctx, s.docker, s.cfg.Network)
		if err != nil || network.Name != s.cfg.Network || !network.Internal || network.Owner != ownerValue || network.Contract != networkContractValue {
			return "", "", &StageError{Stage: "network verification", Err: errors.New("managed network identity changed during the invocation")}
		}
		containers, err := networkContainers(ctx, s.docker, s.cfg.Network)
		if err != nil || len(containers) != 1 || containers[0] != s.cfg.ProxyContainer {
			return "", "", &StageError{Stage: "network verification", Err: errors.New("managed network attachments changed during the invocation")}
		}
		proxy, err := inspectProxy(ctx, s.docker, s.cfg.ProxyContainer, s.cfg.Network)
		if err != nil || !proxyMatches(proxy, s.imageID, s.contract) {
			return "", "", &StageError{Stage: "proxy verification", Err: errors.New("managed proxy identity, health, hardening, or attachments changed during the invocation")}
		}
		return s.cfg.Network, s.cfg.ProxyURL, nil
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	lock, err := acquireLifecycleLock(ctx, s.cfg.Network)
	if err != nil {
		return "", "", &StageError{Stage: "coordination", Err: err}
	}
	s.lock = lock
	fallback, err := collisionFreeConfig(ctx, s.docker, s.cfg)
	if err != nil {
		s.releaseLock()
		return "", "", &StageError{Stage: "resource inspection", Err: err}
	}
	if fallback != s.cfg {
		s.releaseLock()
		s.cfg = fallback
		s.fallbackUsed = true
		lock, err = acquireLifecycleLock(ctx, s.cfg.Network)
		if err != nil {
			return "", "", &StageError{Stage: "coordination", Err: err}
		}
		s.lock = lock
	}
	imageID, contract, err := ensureAsset(ctx, s.docker)
	if err != nil {
		s.releaseLock()
		return "", "", &StageError{Stage: "image preparation", Err: err}
	}
	s.imageID, s.contract = imageID, contract
	created, err := ensureNetwork(ctx, s.docker, s.cfg.Network, s.cfg.ProxyContainer, networkContractValue)
	if err != nil {
		s.releaseLock()
		return "", "", &StageError{Stage: "network preparation", Err: err}
	}
	s.networkCreated = created
	created, err = ensureProxy(ctx, s.docker, s.cfg, imageID, contract)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), proxyCleanupTimeout)
		_ = s.cleanupLocked(cleanupCtx)
		cancel()
		s.releaseLock()
		return "", "", &StageError{Stage: "proxy preparation", Err: err}
	}
	s.containerCreated = created
	s.ensured = true
	if s.cfg.Persistent {
		s.releaseLock()
	}
	return s.cfg.Network, s.cfg.ProxyURL, nil
}

// Notice reports when Vuelta avoided configured names that were already
// occupied. It does not expose ownership labels or require manual recovery.
func (s *Session) Notice() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.fallbackUsed {
		return ""
	}
	return "configured Docker egress names were already in use; Vuelta left those resources unchanged and used an isolated managed egress for this command"
}

// Close cleans resources created only for this invocation. Reused resources
// and explicitly persistent resources are never removed.
func (s *Session) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.releaseLock()
	if s.cfg.Persistent {
		return nil
	}
	return s.cleanupLocked(ctx)
}

func (s *Session) cleanupLocked(ctx context.Context) error {
	var errs []error
	if s.containerCreated {
		if _, err := s.docker.Run(ctx, dockerexec.Request{
			Args:   []string{"container", "rm", "--force", s.cfg.ProxyContainer},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); err != nil {
			errs = append(errs, fmt.Errorf("remove owned proxy: %w", err))
		} else {
			s.containerCreated = false
		}
	}
	if s.networkCreated {
		if _, err := s.docker.Run(ctx, dockerexec.Request{
			Args:   []string{"network", "rm", s.cfg.Network},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); err != nil {
			errs = append(errs, fmt.Errorf("remove owned network: %w", err))
		} else {
			s.networkCreated = false
		}
	}
	return errors.Join(errs...)
}

func (s *Session) releaseLock() {
	if s.lock != nil {
		_ = s.lock.Close()
		s.lock = nil
	}
}

type assetIdentity struct {
	ID           string `json:"id"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	User         string `json:"user"`
	Contract     string `json:"contract"`
}

func ensureAsset(ctx context.Context, docker dockerexec.Runner) (string, string, error) {
	contract := assetContract()
	tag := "vuelta-egress-cache:" + contract
	if identity, err := inspectAsset(ctx, docker, tag, contract); err == nil {
		return identity.ID, contract, nil
	}
	root, err := os.MkdirTemp("", "vuelta-egress-build-")
	if err != nil {
		return "", "", fmt.Errorf("create embedded proxy build context: %w", err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	proxyDir := filepath.Join(root, "egressproxy")
	if err := os.Mkdir(proxyDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create embedded proxy source directory: %w", err)
	}
	files := map[string][]byte{
		"Dockerfile": []byte(proxyDockerfile), "go.mod": []byte(egressproxy.ModuleSource),
		"main.go": []byte(egressproxy.MainSource), filepath.Join("egressproxy", "proxy.go"): egressproxy.Source,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			return "", "", fmt.Errorf("materialize embedded proxy input: %w", err)
		}
	}
	iidPath := filepath.Join(root, "image.id")
	buildCtx, cancel := context.WithTimeout(ctx, proxyBuildTimeout)
	defer cancel()
	if _, err := docker.Run(buildCtx, dockerexec.Request{
		Args: []string{"build", "--pull", "--label", contractLabel + "=" + contract, "--file", "Dockerfile", "--iidfile", iidPath, "."}, Dir: root,
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
	}); err != nil {
		return "", "", fmt.Errorf("build embedded proxy image: %w", err)
	}
	iid, err := os.ReadFile(iidPath)
	if err != nil {
		return "", "", fmt.Errorf("read embedded proxy image ID: %w", err)
	}
	imageID := strings.TrimSpace(string(iid))
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(imageID) {
		return "", "", errors.New("embedded proxy build returned a malformed image ID")
	}
	if _, err := inspectAsset(ctx, docker, imageID, contract); err != nil {
		return "", "", err
	}
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"image", "tag", imageID, tag},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return "", "", fmt.Errorf("publish validated proxy cache tag: %w", err)
	}
	return imageID, contract, nil
}

func assetContract() string {
	payload := struct {
		Version    int    `json:"version"`
		Dockerfile string `json:"dockerfile"`
		Module     string `json:"module"`
		Main       string `json:"main"`
		Proxy      []byte `json:"proxy"`
		Rules      string `json:"rules"`
	}{assetContractVersion, proxyDockerfile, egressproxy.ModuleSource, egressproxy.MainSource, egressproxy.Source, allowRules}
	data, _ := json.Marshal(payload)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func inspectAsset(ctx context.Context, docker dockerexec.Runner, image, contract string) (assetIdentity, error) {
	format := `{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}},"contract":{{json (index .Config.Labels "` + contractLabel + `")}}}`
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"image", "inspect", "--format", format, image},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 1024},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return assetIdentity{}, errors.New("managed proxy image is not present in the approved Docker daemon")
	}
	var identity assetIdentity
	if err := json.Unmarshal(result.Stdout, &identity); err != nil {
		return assetIdentity{}, errors.New("approved Docker daemon returned malformed proxy image metadata")
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(identity.ID) || identity.OS != "linux" || identity.User != proxyUser || identity.Contract != contract {
		return assetIdentity{}, errors.New("managed proxy image identity, OS, or user is invalid")
	}
	if _, err := dockerexec.NormalizeArchitecture(identity.Architecture); err != nil {
		return assetIdentity{}, errors.New("managed proxy image architecture is unsupported")
	}
	return identity, nil
}

type networkIdentity struct {
	Name           string `json:"name"`
	Internal       bool   `json:"internal"`
	Owner          string `json:"owner"`
	Contract       string `json:"contract"`
	ContainerCount int    `json:"container_count"`
}

func collisionFreeConfig(ctx context.Context, docker dockerexec.Runner, configured config.EgressConfig) (config.EgressConfig, error) {
	conflict := false
	if identity, err := inspectNetwork(ctx, docker, configured.Network); err == nil {
		if identity.Name != configured.Network || !identity.Internal || identity.Owner != ownerValue || identity.Contract != networkContractValue {
			conflict = true
		} else {
			containers, attachmentsErr := networkContainers(ctx, docker, configured.Network)
			if attachmentsErr != nil {
				return config.EgressConfig{}, attachmentsErr
			}
			if len(containers) > 1 || (len(containers) == 1 && containers[0] != configured.ProxyContainer) {
				conflict = true
			}
		}
	}
	if owner, err := inspectContainerOwner(ctx, docker, configured.ProxyContainer); err == nil && owner != ownerValue {
		conflict = true
	}
	if !conflict {
		return configured, nil
	}
	sum := sha256.Sum256([]byte(configured.Network + "\x00" + configured.ProxyContainer + "\x00" + configured.ProxyURL))
	suffix := fmt.Sprintf("%x", sum[:6])
	proxy := "vuelta-managed-egress-proxy-" + suffix
	configured.Network = "vuelta-managed-egress-" + suffix
	configured.ProxyContainer = proxy
	configured.ProxyURL = "http://" + proxy + ":3128"
	return configured, nil
}

func inspectContainerOwner(ctx context.Context, docker dockerexec.Runner, name string) (string, error) {
	format := `{"owner":{{json (index .Config.Labels "` + ownerLabel + `")}}}`
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"container", "inspect", "--format", format, name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 256},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return "", err
	}
	var identity struct {
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(result.Stdout, &identity); err != nil {
		return "", errors.New("approved Docker daemon returned malformed container ownership metadata")
	}
	return identity.Owner, nil
}

func ensureNetwork(ctx context.Context, docker dockerexec.Runner, name, proxyContainer, contract string) (bool, error) {
	identity, err := inspectNetwork(ctx, docker, name)
	if err == nil {
		if identity.Name != name || !identity.Internal || identity.Owner != ownerValue || identity.Contract != contract {
			return false, fmt.Errorf("network %q exists but is not the expected Vuelta-owned internal network", name)
		}
		containers, containerErr := networkContainers(ctx, docker, name)
		if containerErr != nil {
			return false, containerErr
		}
		if len(containers) > 1 || (len(containers) == 1 && containers[0] != proxyContainer) {
			return false, fmt.Errorf("network %q has an unexpected container attachment", name)
		}
		return false, nil
	}
	_, createErr := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"network", "create", "--internal", "--label", ownerLabel + "=" + ownerValue, "--label", contractLabel + "=" + contract, name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 256},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if createErr != nil {
		identity, inspectErr := inspectNetwork(ctx, docker, name)
		if inspectErr != nil || identity.Name != name || !identity.Internal || identity.Owner != ownerValue || identity.Contract != contract {
			return false, fmt.Errorf("create owned internal network: %w", createErr)
		}
		return false, nil
	}
	return true, nil
}

func networkContainers(ctx context.Context, docker dockerexec.Runner, name string) ([]string, error) {
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"network", "inspect", "--format", `{{range .Containers}}{{println .Name}}{{end}}`, name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return nil, fmt.Errorf("inspect managed network attachments: %w", err)
	}
	lines := strings.Fields(string(result.Stdout))
	return lines, nil
}

func inspectNetwork(ctx context.Context, docker dockerexec.Runner, name string) (networkIdentity, error) {
	format := `{"name":{{json .Name}},"internal":{{json .Internal}},"owner":{{json (index .Labels "` + ownerLabel + `")}},"contract":{{json (index .Labels "` + contractLabel + `")}},"container_count":{{len .Containers}}}`
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"network", "inspect", "--format", format, name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 1024},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return networkIdentity{}, err
	}
	var identity networkIdentity
	if err := json.Unmarshal(result.Stdout, &identity); err != nil {
		return networkIdentity{}, errors.New("approved Docker daemon returned malformed managed network metadata")
	}
	return identity, nil
}

type containerIdentity struct {
	ID           string   `json:"id"`
	Image        string   `json:"image"`
	Running      bool     `json:"running"`
	Health       string   `json:"health"`
	Owner        string   `json:"owner"`
	Contract     string   `json:"contract"`
	ReadOnly     bool     `json:"read_only"`
	User         string   `json:"user"`
	NetworkMode  string   `json:"network_mode"`
	NetworkCount int      `json:"network_count"`
	OnInternal   bool     `json:"on_internal"`
	OnBridge     bool     `json:"on_bridge"`
	CapDrop      []string `json:"cap_drop"`
	SecurityOpt  []string `json:"security_opt"`
	Memory       int64    `json:"memory"`
	PidsLimit    int64    `json:"pids_limit"`
	NanoCPUs     int64    `json:"nano_cpus"`
}

func ensureProxy(ctx context.Context, docker dockerexec.Runner, cfg config.EgressConfig, imageID, contract string) (bool, error) {
	identity, err := inspectProxy(ctx, docker, cfg.ProxyContainer, cfg.Network)
	if err == nil {
		if identity.Owner != ownerValue {
			return false, fmt.Errorf("container name %q is owned by another application", cfg.ProxyContainer)
		}
		if proxyMatches(identity, imageID, contract) {
			return false, nil
		}
		if _, err := docker.Run(ctx, dockerexec.Request{
			Args:   []string{"container", "rm", "--force", cfg.ProxyContainer},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); err != nil {
			return false, fmt.Errorf("replace stale owned proxy: %w", err)
		}
	}
	created, err := createProxy(ctx, docker, cfg, imageID, contract)
	if err != nil {
		if raced, inspectErr := inspectProxy(ctx, docker, cfg.ProxyContainer, cfg.Network); inspectErr == nil && raced.Owner == ownerValue && proxyMatches(raced, imageID, contract) {
			return false, nil
		}
		return false, err
	}
	return created, nil
}

func proxyMatches(identity containerIdentity, imageID, contract string) bool {
	return identity.Image == imageID && identity.Contract == contract && identity.Running && identity.Health == "healthy" &&
		identity.ReadOnly && identity.User == proxyUser && identity.NetworkCount == 2 && identity.OnInternal && identity.OnBridge &&
		len(identity.CapDrop) == 1 && strings.EqualFold(identity.CapDrop[0], "ALL") &&
		len(identity.SecurityOpt) == 1 && identity.SecurityOpt[0] == "no-new-privileges:true" &&
		identity.Memory == 64<<20 && identity.PidsLimit == 64 && identity.NanoCPUs == 500_000_000 &&
		(identity.NetworkMode == "default" || identity.NetworkMode == "bridge")
}

func createProxy(ctx context.Context, docker dockerexec.Runner, cfg config.EgressConfig, imageID, contract string) (bool, error) {
	args := []string{
		"container", "create", "--name", cfg.ProxyContainer,
		"--label", ownerLabel + "=" + ownerValue, "--label", contractLabel + "=" + contract,
		"--network", "bridge", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", proxyUser, "--cpus", "0.50", "--memory", "64m", "--pids-limit", "64",
		"--env", "VUELTA_EGRESS_ALLOW_RULES=" + allowRules, imageID,
	}
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args: args, Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 256},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return false, fmt.Errorf("create owned proxy: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), proxyCleanupTimeout)
			_, _ = docker.Run(cleanupCtx, dockerexec.Request{Args: []string{"container", "rm", "--force", cfg.ProxyContainer}, Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10}})
			cancel()
		}
	}()
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"network", "connect", cfg.Network, cfg.ProxyContainer},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return false, fmt.Errorf("attach owned proxy to internal network: %w", err)
	}
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"container", "start", cfg.ProxyContainer},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 256},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return false, fmt.Errorf("start owned proxy: %w", err)
	}
	healthCtx, cancel := context.WithTimeout(ctx, proxyHealthTimeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		identity, inspectErr := inspectProxy(healthCtx, docker, cfg.ProxyContainer, cfg.Network)
		if inspectErr == nil && proxyMatches(identity, imageID, contract) {
			cleanup = false
			return true, nil
		}
		select {
		case <-healthCtx.Done():
			return false, errors.New("owned proxy did not become healthy with the expected identity and network attachments")
		case <-ticker.C:
		}
	}
}

func inspectProxy(ctx context.Context, docker dockerexec.Runner, name, network string) (containerIdentity, error) {
	format := `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}},"owner":{{json (index .Config.Labels "` + ownerLabel + `")}},"contract":{{json (index .Config.Labels "` + contractLabel + `")}},"read_only":{{json .HostConfig.ReadonlyRootfs}},"user":{{json .Config.User}},"network_mode":{{json .HostConfig.NetworkMode}},"network_count":{{len .NetworkSettings.Networks}},"on_internal":{{if index .NetworkSettings.Networks "` + network + `"}}true{{else}}false{{end}},"on_bridge":{{if index .NetworkSettings.Networks "bridge"}}true{{else}}false{{end}},"cap_drop":{{json .HostConfig.CapDrop}},"security_opt":{{json .HostConfig.SecurityOpt}},"memory":{{json .HostConfig.Memory}},"pids_limit":{{json .HostConfig.PidsLimit}},"nano_cpus":{{json .HostConfig.NanoCpus}}}`
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"container", "inspect", "--format", format, name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 2048},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return containerIdentity{}, err
	}
	var identity containerIdentity
	if err := json.Unmarshal(result.Stdout, &identity); err != nil {
		return containerIdentity{}, errors.New("approved Docker daemon returned malformed managed proxy metadata")
	}
	return identity, nil
}
