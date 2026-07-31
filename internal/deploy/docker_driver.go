package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/gateway"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/history"
)

const (
	dockerOutputLimit = 1 << 20
	ownerLabel        = "com.luckyfoxdesign.vuelta.owner"
	projectLabel      = "com.luckyfoxdesign.vuelta.project"
	slotLabel         = "com.luckyfoxdesign.vuelta.slot"
)

var dockerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// DockerDriverOptions binds production deployment to one attested Docker
// boundary and one protected Vuelta state directory.
type DockerDriverOptions struct {
	Runner          dockerexec.Runner
	StateDir        string
	GatewayImage    string
	RegistryUser    string
	RegistryToken   string
	HealthTimeout   time.Duration
	PollInterval    time.Duration
	MinFreeMemoryMB int
	MinFreeDiskMB   int
	ResourceProbe   ResourceProbe
}

// DockerDriver implements the fixed Docker/Compose/gateway operations used by
// Runtime. It never reads an env file or emits raw inspection/config output.
type DockerDriver struct {
	options DockerDriverOptions
	mutex   sync.Mutex
	adopted map[string]string
}

// NewDockerDriver validates global machine authority.
func NewDockerDriver(options DockerDriverOptions) (*DockerDriver, error) {
	if options.Runner == nil {
		return nil, errors.New("docker deployment runner is required")
	}
	if !filepath.IsAbs(options.StateDir) || filepath.Clean(options.StateDir) != options.StateDir {
		return nil, errors.New("docker deployment state directory must be clean and absolute")
	}
	if !strings.Contains(options.GatewayImage, "@sha256:") {
		return nil, errors.New("gateway image must be digest-pinned")
	}
	if !dockerNamePattern.MatchString(options.RegistryUser) || options.RegistryToken == "" {
		return nil, errors.New("bounded registry user and token are required")
	}
	if err := ensureProtectedDirectory(options.StateDir); err != nil {
		return nil, err
	}
	if options.MinFreeMemoryMB < 0 || options.MinFreeDiskMB < 0 {
		return nil, errors.New("deployment resource thresholds cannot be negative")
	}
	if options.ResourceProbe == nil {
		options.ResourceProbe = hostResources
	}
	return &DockerDriver{options: options, adopted: make(map[string]string)}, nil
}

func (d *DockerDriver) Preflight(ctx context.Context, contract Contract) error {
	if len(contract.Services) == 0 {
		return errors.New("at least one release service is required")
	}
	if len(contract.ExternalNetworks) != 1 {
		return errors.New("exactly one external proxy network must be discovered")
	}
	if contract.TrafficService == "" || contract.InternalPort <= 0 || contract.HealthPath == "" {
		return errors.New("one healthy HTTP traffic service is required")
	}
	if !dockerNamePattern.MatchString(contract.Project) ||
		!dockerNamePattern.MatchString(contract.TrafficService) ||
		!dockerNamePattern.MatchString(contract.StableUpstream) ||
		!dockerNamePattern.MatchString(contract.ExternalNetworks[0]) {
		return errors.New("deployment contract contains an invalid Docker identity")
	}
	_, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"network", "inspect", contract.ExternalNetworks[0]},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 64 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return errors.New("external proxy network is unavailable")
	}
	if d.options.MinFreeMemoryMB > 0 || d.options.MinFreeDiskMB > 0 {
		resources, probeErr := d.options.ResourceProbe(d.options.StateDir)
		if probeErr != nil {
			return fmt.Errorf("host resource preflight: %w", probeErr)
		}
		if resources.FreeMemoryMB < d.options.MinFreeMemoryMB {
			return fmt.Errorf(
				"host resource preflight: %d MiB memory available, minimum is %d MiB",
				resources.FreeMemoryMB, d.options.MinFreeMemoryMB,
			)
		}
		if resources.FreeDiskMB < d.options.MinFreeDiskMB {
			return fmt.Errorf(
				"host resource preflight: %d MiB disk available, minimum is %d MiB",
				resources.FreeDiskMB, d.options.MinFreeDiskMB,
			)
		}
	}
	return nil
}

func (d *DockerDriver) PullExact(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
) (string, error) {
	login := dockerexec.Request{
		Args:   []string{"login", "ghcr.io", "--username", d.options.RegistryUser, "--password-stdin"},
		Stdin:  strings.NewReader(d.options.RegistryToken),
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}
	if _, err := d.run(ctx, login); err != nil {
		return "", errors.New("GHCR login failed")
	}
	defer func() {
		_, _ = d.run(context.Background(), dockerexec.Request{
			Args:   []string{"logout", "ghcr.io"},
			Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		})
	}()
	tag := release.ImageRepository + ":" + release.SourceCommit
	if _, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"pull", tag},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
	}); err != nil {
		return "", errors.New("pull candidate image failed")
	}
	metadata, err := d.inspectImage(ctx, tag)
	if err != nil {
		return "", err
	}
	expectedSource := "https://github.com/" + contract.Repository
	if metadata.Labels["org.opencontainers.image.source"] != expectedSource ||
		metadata.Labels["org.opencontainers.image.revision"] != release.SourceCommit {
		return "", errors.New("candidate OCI source or revision label mismatch")
	}
	prefix := release.ImageRepository + "@"
	for _, repoDigest := range metadata.RepoDigests {
		if strings.HasPrefix(repoDigest, prefix) {
			digest := strings.TrimPrefix(repoDigest, prefix)
			if historyDigestPattern.MatchString(digest) {
				return digest, nil
			}
		}
	}
	return "", errors.New("candidate image has no exact allowlisted RepoDigest")
}

var historyDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func (d *DockerDriver) Current(ctx context.Context, contract Contract) (RunningSlot, error) {
	container := contract.StableUpstream
	configPath := d.gatewayConfigPath(contract)
	if config, err := gateway.Load(configPath); err == nil {
		target, parseErr := url.Parse(config.Upstream)
		if parseErr == nil && dockerNamePattern.MatchString(target.Hostname()) {
			container = target.Hostname()
		}
	}
	view, err := d.inspectContainer(ctx, container)
	if err != nil {
		return RunningSlot{}, errors.New("current container is unavailable")
	}
	metadata, err := d.inspectImage(ctx, view.Image)
	if err != nil {
		return RunningSlot{}, err
	}
	digest := exactDigest(metadata.RepoDigests)
	if digest == "" && historyDigestPattern.MatchString(view.Image) {
		digest = view.Image
	}
	if digest == "" {
		return RunningSlot{}, errors.New("current container image has no immutable RepoDigest")
	}
	slot := view.Labels[slotLabel]
	if slot != "blue" && slot != "green" {
		slot = "blue"
	}
	networkIPs := make(map[string]string, len(view.Networks))
	for name, network := range view.Networks {
		networkIPs[name] = network.IPAddress
	}
	return RunningSlot{
		Name: contract.Project, Slot: slot, Digest: digest,
		Commit:    view.Labels["org.opencontainers.image.revision"],
		Container: strings.TrimPrefix(view.Name, "/"), Labels: view.Labels, NetworkIPs: networkIPs,
	}, nil
}

func (d *DockerDriver) ChangedMigrations(
	ctx context.Context,
	contract Contract,
	previousCommit, candidateCommit string,
) ([]string, error) {
	if len(contract.MigrationPaths) == 0 {
		return nil, nil
	}
	if !commitPattern.MatchString(previousCommit) || !commitPattern.MatchString(candidateCommit) {
		return nil, errors.New("migration comparison requires exact previous and candidate commits")
	}
	args := []string{"diff-tree", "--no-commit-id", "--name-only", "-r", previousCommit, candidateCommit, "--"}
	args = append(args, contract.MigrationPaths...)
	output, err := gitexec.Output(ctx, contract.Root, args...)
	if err != nil {
		return nil, err
	}
	var changes []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = filepath.ToSlash(strings.TrimSpace(line))
		if line != "" && !strings.Contains(line, "..") && len(line) <= 4096 {
			changes = append(changes, line)
		}
	}
	return uniqueSorted(changes), nil
}

func (d *DockerDriver) StartCandidate(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	slot string,
) (CandidateSlot, error) {
	if slot != "blue" && slot != "green" {
		return CandidateSlot{}, errors.New("candidate slot is invalid")
	}
	container := slotContainer(contract, slot)
	overlay, err := d.writeComposeOverlay(contract, slot)
	if err != nil {
		return CandidateSlot{}, err
	}
	args := []string{"compose", "--project-directory", contract.Root}
	for _, relative := range contract.ComposeFiles {
		args = append(args, "-f", filepath.Join(contract.Root, relative))
	}
	args = append(args, "-f", overlay, "run", "--detach", "--no-deps", "--name", container, contract.TrafficService)
	image := release.ImageRepository + "@" + release.CandidateDigest
	if _, err := d.run(ctx, dockerexec.Request{
		Args: args, Dir: contract.Root, Env: map[string]string{"VUELTA_IMAGE": image},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 16 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
	}); err != nil {
		return CandidateSlot{}, errors.New("create candidate from Compose contract failed")
	}
	return CandidateSlot{
		Name: contract.Project, Slot: slot, Digest: release.CandidateDigest, Container: container,
	}, nil
}

func (d *DockerDriver) WaitHealthy(ctx context.Context, _ Contract, candidate CandidateSlot) error {
	timeout := d.options.HealthTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	interval := d.options.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		view, err := d.inspectContainer(ctx, candidate.Container)
		if err != nil {
			return err
		}
		switch view.Health {
		case "healthy":
			return nil
		case "unhealthy":
			return errors.New("candidate Docker healthcheck failed")
		}
		if time.Now().After(deadline) {
			return errors.New("candidate Docker healthcheck timed out")
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (d *DockerDriver) SwitchTraffic(
	ctx context.Context,
	contract Contract,
	current RunningSlot,
	candidate CandidateSlot,
) error {
	if err := d.writeGatewayConfig(contract, candidate.Container); err != nil {
		return err
	}
	gatewayName := d.gatewayName(contract)
	exists := d.containerExists(ctx, gatewayName)
	if !exists {
		args := []string{
			"run", "--detach", "--name", gatewayName,
			"--network", contract.ExternalNetworks[0],
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"--pids-limit", "64", "--memory", "64m",
			"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"--mount", "type=bind,src=" + d.gatewayDirectory(contract) + ",dst=/config,readonly",
			"--label", ownerLabel + "=true", "--label", projectLabel + "=" + contract.Project,
		}
		traefik := traefikGatewayLabels(contract, current.Labels)
		if len(traefik) == 0 {
			args = append(args, "--network-alias", contract.StableUpstream)
		} else {
			keys := make([]string, 0, len(traefik))
			for key := range traefik {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				args = append(args, "--label", key+"="+traefik[key])
			}
		}
		args = append(args, d.options.GatewayImage, "--config", "/config/gateway.json")
		if _, err := d.run(ctx, dockerexec.Request{
			Args:   args,
			Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 16 << 10},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
		}); err != nil {
			return errors.New("start Vuelta traffic gateway failed")
		}
		if len(traefik) == 0 {
			if err := d.adoptDNSUpstream(ctx, contract, current); err != nil {
				return err
			}
		}
	} else {
		if _, err := d.run(ctx, dockerexec.Request{
			Args:   []string{"kill", "--signal", "HUP", gatewayName},
			Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); err != nil {
			return errors.New("reload Vuelta traffic gateway failed")
		}
	}
	return d.gatewayCheck(ctx, contract)
}

func (d *DockerDriver) Smoke(ctx context.Context, contract Contract, _ CandidateSlot) error {
	return d.gatewayCheck(ctx, contract)
}

func (d *DockerDriver) ActivateCompanions(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	candidate CandidateSlot,
) error {
	type replacement struct {
		old string
		new CandidateSlot
	}
	var replaced []replacement
	restore := func() {
		for index := len(replaced) - 1; index >= 0; index-- {
			_ = d.RemoveCandidate(context.Background(), contract, replaced[index].new)
			_, _ = d.run(context.Background(), dockerexec.Request{
				Args:   []string{"start", replaced[index].old},
				Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
				Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
			})
		}
	}
	for _, service := range contract.Services {
		if service.Name == contract.TrafficService {
			continue
		}
		if service.ExternalNetwork {
			restore()
			return fmt.Errorf("companion %s is externally routed without a health contract", service.Name)
		}
		old, err := d.findServiceContainer(ctx, service)
		if err != nil {
			restore()
			return err
		}
		if _, err := d.run(ctx, dockerexec.Request{
			Args:   []string{"stop", "--time", "30", old},
			Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
		}); err != nil {
			restore()
			return fmt.Errorf("stop companion %s: %w", service.Name, err)
		}
		started, err := d.startComposeService(ctx, contract, release, candidate.Slot, service.Name)
		if err != nil {
			_, _ = d.run(context.Background(), dockerexec.Request{
				Args:   []string{"start", old},
				Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
				Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
			})
			restore()
			return err
		}
		replaced = append(replaced, replacement{old: old, new: started})
		view, inspectErr := d.inspectContainer(ctx, started.Container)
		if inspectErr != nil || view.State != "running" {
			restore()
			return fmt.Errorf("companion %s did not remain running", service.Name)
		}
	}
	return nil
}

func (d *DockerDriver) RestoreTraffic(ctx context.Context, contract Contract, previous RunningSlot) error {
	container := d.resolveAdopted(contract.Project, previous.Container)
	if _, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"start", container},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil && !d.containerRunning(ctx, container) {
		return errors.New("start previous slot failed")
	}
	if err := d.writeGatewayConfig(contract, container); err != nil {
		return err
	}
	if _, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"kill", "--signal", "HUP", d.gatewayName(contract)},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return errors.New("restore gateway route failed")
	}
	return d.gatewayCheck(ctx, contract)
}

func (d *DockerDriver) Drain(ctx context.Context, _ Contract, _ RunningSlot, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (d *DockerDriver) Stop(ctx context.Context, contract Contract, previous RunningSlot) error {
	container := d.resolveAdopted(contract.Project, previous.Container)
	_, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"stop", "--time", "30", container},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return errors.New("stop previous slot failed")
	}
	return nil
}

func (d *DockerDriver) RemoveCandidate(ctx context.Context, _ Contract, candidate CandidateSlot) error {
	view, err := d.inspectContainer(ctx, candidate.Container)
	if err != nil {
		return nil
	}
	if view.Labels[ownerLabel] != "true" || view.Labels[projectLabel] != candidate.Name ||
		view.Labels[slotLabel] != candidate.Slot {
		return errors.New("refuse to remove a container not owned by this Vuelta slot")
	}
	_, err = d.run(ctx, dockerexec.Request{
		Args:   []string{"rm", "--force", candidate.Container},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return errors.New("remove failed candidate container failed")
	}
	return nil
}

type imageMetadata struct {
	RepoDigests []string          `json:"repo_digests"`
	Labels      map[string]string `json:"labels"`
}

type containerView struct {
	Name     string                      `json:"name"`
	Image    string                      `json:"image"`
	State    string                      `json:"state"`
	Health   string                      `json:"health"`
	Labels   map[string]string           `json:"labels"`
	Networks map[string]containerNetwork `json:"networks"`
}

type containerNetwork struct {
	IPAddress string `json:"IPAddress"`
}

func (d *DockerDriver) inspectImage(ctx context.Context, reference string) (imageMetadata, error) {
	template := `{"repo_digests":{{json .RepoDigests}},"labels":{{json .Config.Labels}}}`
	result, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"image", "inspect", "--format", template, reference},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: dockerOutputLimit},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return imageMetadata{}, errors.New("inspect image metadata failed")
	}
	var metadata imageMetadata
	if err := decodeBoundedJSON(result.Stdout, &metadata); err != nil {
		return imageMetadata{}, err
	}
	if metadata.Labels == nil {
		metadata.Labels = map[string]string{}
	}
	return metadata, nil
}

func (d *DockerDriver) inspectContainer(ctx context.Context, name string) (containerView, error) {
	if !dockerNamePattern.MatchString(name) {
		return containerView{}, errors.New("container name is invalid")
	}
	template := `{"name":{{json .Name}},"image":{{json .Image}},"state":{{json .State.Status}},` +
		`"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}},` +
		`"labels":{{json .Config.Labels}},"networks":{{json .NetworkSettings.Networks}}}`
	result, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"container", "inspect", "--format", template, name},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: dockerOutputLimit},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return containerView{}, errors.New("inspect container metadata failed")
	}
	var view containerView
	if err := decodeBoundedJSON(result.Stdout, &view); err != nil {
		return containerView{}, err
	}
	if view.Labels == nil {
		view.Labels = map[string]string{}
	}
	return view, nil
}

func (d *DockerDriver) writeComposeOverlay(contract Contract, slot string) (string, error) {
	return d.writeComposeServiceOverlay(contract, slot, contract.TrafficService)
}

func (d *DockerDriver) writeComposeServiceOverlay(contract Contract, slot, service string) (string, error) {
	directory := filepath.Join(d.options.StateDir, "overlays", contract.Project)
	if err := ensureProtectedDirectory(directory); err != nil {
		return "", err
	}
	path := filepath.Join(directory, slot+"-"+service+".yml")
	body := fmt.Sprintf(`services:
  %s:
    image: "${VUELTA_IMAGE:?}"
    build: null
    container_name: null
    labels:
      %s: "true"
      %s: %q
      %s: %q
`, service, ownerLabel, projectLabel, contract.Project, slotLabel, slot)
	if err := writeProtectedAtomic(path, []byte(body)); err != nil {
		return "", err
	}
	return path, nil
}

func (d *DockerDriver) startComposeService(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	slot, service string,
) (CandidateSlot, error) {
	if !dockerNamePattern.MatchString(service) {
		return CandidateSlot{}, errors.New("companion service name is invalid")
	}
	container := "vuelta-" + contract.Project + "-" + slot + "-" + service
	overlay, err := d.writeComposeServiceOverlay(contract, slot, service)
	if err != nil {
		return CandidateSlot{}, err
	}
	args := []string{"compose", "--project-directory", contract.Root}
	for _, relative := range contract.ComposeFiles {
		args = append(args, "-f", filepath.Join(contract.Root, relative))
	}
	args = append(args, "-f", overlay, "run", "--detach", "--no-deps", "--name", container, service)
	image := release.ImageRepository + "@" + release.CandidateDigest
	if _, err := d.run(ctx, dockerexec.Request{
		Args: args, Dir: contract.Root, Env: map[string]string{"VUELTA_IMAGE": image},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 16 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
	}); err != nil {
		return CandidateSlot{}, fmt.Errorf("start companion %s: %w", service, err)
	}
	return CandidateSlot{
		Name: contract.Project, Slot: slot, Digest: release.CandidateDigest, Container: container,
	}, nil
}

func (d *DockerDriver) findServiceContainer(ctx context.Context, service Service) (string, error) {
	if service.ContainerName != "" {
		if d.containerRunning(ctx, service.ContainerName) {
			return service.ContainerName, nil
		}
	}
	result, err := d.run(ctx, dockerexec.Request{
		Args: []string{
			"ps", "--filter", "label=com.docker.compose.service=" + service.Name,
			"--format", "{{.Names}}",
		},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 16 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return "", fmt.Errorf("find running companion %s: %w", service.Name, err)
	}
	var matches []string
	for _, line := range strings.Split(strings.TrimSpace(string(result.Stdout)), "\n") {
		line = strings.TrimSpace(line)
		if dockerNamePattern.MatchString(line) {
			matches = append(matches, line)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("companion %s must match exactly one running Compose container", service.Name)
	}
	return matches[0], nil
}

func (d *DockerDriver) writeGatewayConfig(contract Contract, upstream string) error {
	if !dockerNamePattern.MatchString(upstream) {
		return errors.New("gateway upstream container is invalid")
	}
	directory := d.gatewayDirectory(contract)
	if err := ensureProtectedDirectory(directory); err != nil {
		return err
	}
	data, err := json.Marshal(gateway.Config{
		Listen:   ":" + strconv.Itoa(contract.InternalPort),
		Upstream: "http://" + upstream + ":" + strconv.Itoa(contract.InternalPort),
	})
	if err != nil {
		return err
	}
	return writeProtectedAtomic(d.gatewayConfigPath(contract), append(data, '\n'))
}

func (d *DockerDriver) gatewayCheck(ctx context.Context, contract Contract) error {
	path := contract.HealthPath
	if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return errors.New("gateway health path is invalid")
	}
	checkURL := "http://127.0.0.1:" + strconv.Itoa(contract.InternalPort) + path
	_, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"exec", d.gatewayName(contract), "/vuelta-gateway", "--check", checkURL},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	})
	if err != nil {
		return errors.New("gateway route smoke check failed")
	}
	return nil
}

func (d *DockerDriver) adoptDNSUpstream(ctx context.Context, contract Contract, current RunningSlot) error {
	network := contract.ExternalNetworks[0]
	ip := current.NetworkIPs[network]
	if net.ParseIP(ip) == nil {
		return errors.New("current upstream has no fixed address on the external network")
	}
	oldName := current.Container
	newName := slotContainer(contract, current.Slot)
	if oldName != newName {
		if _, err := d.run(ctx, dockerexec.Request{
			Args:   []string{"rename", oldName, newName},
			Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
		}); err != nil {
			return errors.New("rename adopted previous slot failed")
		}
	}
	if _, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"network", "disconnect", network, newName},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return errors.New("detach adopted previous slot failed")
	}
	if _, err := d.run(ctx, dockerexec.Request{
		Args:   []string{"network", "connect", "--ip", ip, "--alias", newName, network, newName},
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
	}); err != nil {
		return errors.New("reattach adopted previous slot failed")
	}
	d.mutex.Lock()
	d.adopted[contract.Project] = newName
	d.mutex.Unlock()
	return nil
}

func traefikGatewayLabels(contract Contract, existing map[string]string) map[string]string {
	hasTraefik := existing["traefik.enable"] == "true"
	for key := range existing {
		if strings.HasPrefix(key, "traefik.http.routers.") {
			hasTraefik = true
		}
	}
	if !hasTraefik {
		return nil
	}
	router := "vuelta-" + contract.Project
	service := router
	labels := map[string]string{
		"traefik.enable":                                                 "true",
		"traefik.docker.network":                                         contract.ExternalNetworks[0],
		"traefik.http.routers." + router + ".priority":                   "2147483000",
		"traefik.http.routers." + router + ".service":                    service,
		"traefik.http.services." + service + ".loadbalancer.server.port": strconv.Itoa(contract.InternalPort),
	}
	allowedSuffixes := map[string]bool{
		"rule": true, "entrypoints": true, "middlewares": true, "tls": true,
		"tls.certresolver": true, "tls.domains[0].main": true, "tls.domains[0].sans": true,
	}
	for key, value := range existing {
		const prefix = "traefik.http.routers."
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(key, prefix)
		dot := strings.IndexByte(remainder, '.')
		if dot < 1 {
			continue
		}
		suffix := remainder[dot+1:]
		if allowedSuffixes[suffix] && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00") {
			labels["traefik.http.routers."+router+"."+suffix] = value
		}
	}
	if labels["traefik.http.routers."+router+".rule"] == "" {
		return nil
	}
	return labels
}

func (d *DockerDriver) run(ctx context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	return d.options.Runner.Run(ctx, request)
}

func (d *DockerDriver) containerExists(ctx context.Context, name string) bool {
	_, err := d.inspectContainer(ctx, name)
	return err == nil
}

func (d *DockerDriver) containerRunning(ctx context.Context, name string) bool {
	view, err := d.inspectContainer(ctx, name)
	return err == nil && view.State == "running"
}

func (d *DockerDriver) resolveAdopted(project, fallback string) string {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if adopted := d.adopted[project]; adopted != "" {
		return adopted
	}
	return fallback
}

func (d *DockerDriver) gatewayName(contract Contract) string {
	return "vuelta-gateway-" + contract.Project
}

func (d *DockerDriver) gatewayDirectory(contract Contract) string {
	return filepath.Join(d.options.StateDir, "gateways", contract.Project)
}

func (d *DockerDriver) gatewayConfigPath(contract Contract) string {
	return filepath.Join(d.gatewayDirectory(contract), "gateway.json")
}

func exactDigest(repoDigests []string) string {
	for _, value := range repoDigests {
		if index := strings.LastIndex(value, "@"); index >= 0 {
			digest := value[index+1:]
			if historyDigestPattern.MatchString(digest) {
				return digest
			}
		}
	}
	return ""
}

func decodeBoundedJSON(data []byte, destination any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || len(data) > dockerOutputLimit {
		return errors.New("docker metadata response is empty or exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return errors.New("docker metadata response is invalid")
	}
	return nil
}

func ensureProtectedDirectory(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create deployment state directory: %w", err)
		}
	case err != nil:
		return fmt.Errorf("inspect deployment state directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return errors.New("deployment state path must be a real directory")
	case info.Mode().Perm()&0o077 != 0:
		return errors.New("deployment state directory permissions are too broad")
	}
	return os.Chmod(path, 0o700)
}

func writeProtectedAtomic(path string, data []byte) error {
	if len(data) > 64<<10 {
		return errors.New("generated deployment file exceeds bounded size")
	}
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".vuelta-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
