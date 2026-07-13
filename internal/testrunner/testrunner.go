// Package testrunner runs a project's docker compose test service against
// the sandboxed working copy.
package testrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

// DefaultTimeout is used when a workspace's test profile does not set one.
const DefaultTimeout = 15 * time.Minute

// Result is the outcome of one test run.
type Result struct {
	Passed bool
	// Output is the combined stdout+stderr of the test command. It is
	// intended for a local 0600 log file only — never forward it to
	// notify as-is (part C §15: no raw logs in webhook/Telegram summaries).
	Output string
}

// Run executes the configured test profile against workDir using
// `docker compose -f <compose_file> run --rm <run_args...> <service>`. The
// compose file is policy-checked first (§8): privileged, host
// network/pid/ipc, docker socket, absolute host mounts, env_file/implicit
// .env, and mutable (non-digest) image tags on the target service are
// rejected before the command ever runs. The deeper sandbox
// network-egress/isolation policy belongs to part F; this is the baseline
// this package's own execution path is responsible for.
func Run(ctx context.Context, workDir string, profile config.TestProfile, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	composePath, composeFile, err := resolveComposeFile(workDir, profile.ComposeFile)
	if err != nil {
		return Result{}, fmt.Errorf("test compose policy: %w", err)
	}
	if err := checkPolicy(workDir, composePath, profile.Service); err != nil {
		return Result{}, fmt.Errorf("test compose policy: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{"compose", "-f", composeFile, "run", "--rm", "--no-TTY"}, profile.RunArgs...)
	args = append(args, profile.Service)

	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.Dir = workDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	runErr := cmd.Run()
	result := Result{Output: out.String()}

	if runCtx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("test profile timed out after %s", timeout)
	}
	if runErr != nil {
		// A failing test suite is a normal pipeline outcome, not a Go
		// error: the caller decides whether to retry via autofix or skip.
		result.Passed = false
		return result, nil
	}
	result.Passed = true
	return result, nil
}

var digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

type composeFile struct {
	Services composeServices               `yaml:"services"`
	Volumes  map[string]composeNamedVolume `yaml:"volumes"`
	Networks map[string]composeNetwork     `yaml:"networks"`
	Include  interface{}                   `yaml:"include"`
	Configs  interface{}                   `yaml:"configs"`
	Secrets  interface{}                   `yaml:"secrets"`
}

type composeServices map[string]composeService

type composeService struct {
	Privileged        bool                `yaml:"privileged"`
	NetworkMode       string              `yaml:"network_mode"`
	Pid               string              `yaml:"pid"`
	Ipc               string              `yaml:"ipc"`
	EnvFile           interface{}         `yaml:"env_file"`
	Image             string              `yaml:"image"`
	Volumes           []composeVolume     `yaml:"volumes"`
	DependsOn         composeDependencies `yaml:"depends_on"`
	Devices           []interface{}       `yaml:"devices"`
	DeviceCgroupRules []string            `yaml:"device_cgroup_rules"`
	CapAdd            []string            `yaml:"cap_add"`
	CapDrop           []string            `yaml:"cap_drop"`
	SecurityOpt       []string            `yaml:"security_opt"`
	User              string              `yaml:"user"`
	CPUs              string              `yaml:"cpus"`
	MemLimit          string              `yaml:"mem_limit"`
	PidsLimit         int                 `yaml:"pids_limit"`
	Networks          interface{}         `yaml:"networks"`
	Environment       interface{}         `yaml:"environment"`
	Build             interface{}         `yaml:"build"`
	Extends           interface{}         `yaml:"extends"`
	VolumesFrom       interface{}         `yaml:"volumes_from"`
	Configs           interface{}         `yaml:"configs"`
	Secrets           interface{}         `yaml:"secrets"`
	UseAPISocket      bool                `yaml:"use_api_socket"`
}

// composeDependencies accepts both Compose forms: a list of service names and
// a map keyed by service name. The policy deliberately validates optional
// dependencies too: doing so prevents a configuration change from silently
// widening the runner's authority.
type composeDependencies []string

func (d *composeDependencies) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode || item.Value == "" {
				return errors.New("depends_on entries must be service names")
			}
			*d = append(*d, item.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(value.Content); i += 2 {
			name := value.Content[i]
			if name.Kind != yaml.ScalarNode || name.Value == "" {
				return errors.New("depends_on keys must be service names")
			}
			*d = append(*d, name.Value)
		}
	default:
		return errors.New("depends_on must be a list or map")
	}
	return nil
}

type composeVolume struct {
	Type     string
	Source   string
	ReadOnly bool
}

func (v *composeVolume) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		parts := strings.SplitN(value.Value, ":", 3)
		if len(parts) < 2 || parts[0] == "" {
			return fmt.Errorf("invalid short volume syntax %q", value.Value)
		}
		v.Source = parts[0]
		if isBindSource(v.Source) {
			v.Type = "bind"
		} else {
			v.Type = "volume"
		}
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return errors.New("volume must use short or long syntax")
	}
	var raw struct {
		Type     string `yaml:"type"`
		Source   string `yaml:"source"`
		ReadOnly bool   `yaml:"read_only"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	if raw.Type == "" || raw.Source == "" {
		return errors.New("long volume syntax requires type and source")
	}
	v.Type, v.Source, v.ReadOnly = raw.Type, raw.Source, raw.ReadOnly
	return nil
}

type composeNamedVolume struct {
	External   bool        `yaml:"external"`
	Name       string      `yaml:"name"`
	DriverOpts interface{} `yaml:"driver_opts"`
}

type composeNetwork struct {
	Internal   bool        `yaml:"internal"`
	External   bool        `yaml:"external"`
	Name       string      `yaml:"name"`
	DriverOpts interface{} `yaml:"driver_opts"`
}

func checkPolicy(workDir, composePath, service string) error {
	if err := checkNoImplicitEnvFile(filepath.Dir(composePath)); err != nil {
		return err
	}
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", composePath, err)
	}
	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("parse %s: %w", composePath, err)
	}
	if cf.Include != nil {
		return errors.New("top-level include is not allowed")
	}
	if cf.Configs != nil || cf.Secrets != nil {
		return errors.New("top-level configs and secrets are not allowed")
	}
	if _, ok := cf.Services[service]; !ok {
		return fmt.Errorf("service %q not found in %s", service, composePath)
	}
	for name, volume := range cf.Volumes {
		if volume.External || volume.Name != "" || volume.DriverOpts != nil {
			return fmt.Errorf("named volume %q must be local and have no name or driver_opts", name)
		}
	}
	for name, network := range cf.Networks {
		if !network.Internal || network.External || network.Name != "" || network.DriverOpts != nil {
			return fmt.Errorf("network %q must be an unnamed internal test network", name)
		}
	}

	return checkServicePolicy(workDir, cf, service, make(map[string]bool))
}

func checkServicePolicy(workDir string, cf composeFile, service string, checked map[string]bool) error {
	if checked[service] {
		return nil
	}
	checked[service] = true

	svc := cf.Services[service]

	if svc.Privileged {
		return fmt.Errorf("service %q: privileged is not allowed", service)
	}
	if svc.NetworkMode == "host" {
		return fmt.Errorf("service %q: network_mode host is not allowed", service)
	}
	if svc.Pid == "host" {
		return fmt.Errorf("service %q: pid host is not allowed", service)
	}
	if svc.Ipc == "host" {
		return fmt.Errorf("service %q: ipc host is not allowed", service)
	}
	if svc.EnvFile != nil {
		return fmt.Errorf("service %q: env_file is not allowed", service)
	}
	if len(svc.Devices) != 0 || len(svc.DeviceCgroupRules) != 0 {
		return fmt.Errorf("service %q: devices are not allowed", service)
	}
	if len(svc.CapAdd) != 0 {
		return fmt.Errorf("service %q: cap_add is not allowed", service)
	}
	if svc.UseAPISocket {
		return fmt.Errorf("service %q: use_api_socket is not allowed", service)
	}
	if svc.Extends != nil || svc.VolumesFrom != nil || svc.Configs != nil || svc.Secrets != nil {
		return fmt.Errorf("service %q: extends, volumes_from, configs, and secrets are not allowed", service)
	}
	if svc.Image != "" && !digestPinned.MatchString(svc.Image) {
		return fmt.Errorf("service %q: image %q must be pinned by digest", service, svc.Image)
	}
	for _, v := range svc.Volumes {
		if err := checkVolume(workDir, cf.Volumes, service, v); err != nil {
			return err
		}
	}
	if err := checkBuildContext(workDir, service, svc.Build); err != nil {
		return err
	}
	for _, dependency := range svc.DependsOn {
		if _, ok := cf.Services[dependency]; !ok {
			return fmt.Errorf("service %q: dependency %q not found", service, dependency)
		}
		if err := checkServicePolicy(workDir, cf, dependency, checked); err != nil {
			return err
		}
	}
	if !hasAllCapabilityDrop(svc.CapDrop) {
		return fmt.Errorf("service %q: cap_drop must include ALL", service)
	}
	if !hasNoNewPrivileges(svc.SecurityOpt) {
		return fmt.Errorf("service %q: security_opt must include no-new-privileges", service)
	}
	if isRootUser(svc.User) {
		return fmt.Errorf("service %q: user must be an explicit non-root UID", service)
	}
	if svc.CPUs == "" || svc.MemLimit == "" || svc.PidsLimit <= 0 {
		return fmt.Errorf("service %q: cpus, mem_limit, and pids_limit are required", service)
	}
	if err := checkInternalNetworks(cf.Networks, service, svc.Networks); err != nil {
		return err
	}
	if err := checkEnvironment(service, svc.Environment); err != nil {
		return err
	}
	return nil
}

func hasAllCapabilityDrop(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "ALL") {
			return true
		}
	}
	return false
}

func hasNoNewPrivileges(values []string) bool {
	for _, value := range values {
		if value == "no-new-privileges:true" || value == "no-new-privileges" {
			return true
		}
	}
	return false
}

func isRootUser(user string) bool {
	if user == "" {
		return true
	}
	uid := strings.SplitN(user, ":", 2)[0]
	return uid == "0" || strings.EqualFold(uid, "root")
}

func checkInternalNetworks(networks map[string]composeNetwork, service string, value interface{}) error {
	var names []string
	switch configured := value.(type) {
	case []interface{}:
		for _, network := range configured {
			name, ok := network.(string)
			if !ok || name == "" {
				return fmt.Errorf("service %q: invalid network entry", service)
			}
			names = append(names, name)
		}
	case map[string]interface{}:
		for name := range configured {
			names = append(names, name)
		}
	case nil:
		return fmt.Errorf("service %q: an explicit internal test network is required", service)
	default:
		return fmt.Errorf("service %q: invalid networks configuration", service)
	}
	if len(names) == 0 {
		return fmt.Errorf("service %q: an explicit internal test network is required", service)
	}
	for _, name := range names {
		network, ok := networks[name]
		if !ok || !network.Internal || network.External {
			return fmt.Errorf("service %q: network %q must be declared internal", service, name)
		}
	}
	return nil
}

func checkEnvironment(service string, value interface{}) error {
	if value == nil {
		return nil
	}
	// A bare key asks Compose to inherit a host variable. Interpolation also
	// reads host state, so only concrete sandbox test values are permitted.
	text := fmt.Sprint(value)
	if strings.Contains(text, "${") || strings.Contains(text, "$${") {
		return fmt.Errorf("service %q: environment interpolation is not allowed", service)
	}
	switch env := value.(type) {
	case []interface{}:
		for _, item := range env {
			entry, ok := item.(string)
			if !ok || !strings.Contains(entry, "=") {
				return fmt.Errorf("service %q: environment must use explicit KEY=value entries", service)
			}
		}
	case map[string]interface{}:
		for key, item := range env {
			if key == "" || item == nil {
				return fmt.Errorf("service %q: environment must use concrete values", service)
			}
		}
	default:
		return fmt.Errorf("service %q: invalid environment configuration", service)
	}
	return nil
}

func checkVolume(workDir string, volumes map[string]composeNamedVolume, service string, v composeVolume) error {
	switch v.Type {
	case "bind":
		if strings.Contains(v.Source, "docker.sock") {
			return fmt.Errorf("service %q: docker socket mount is not allowed", service)
		}
		if err := checkSandboxPath(workDir, v.Source); err != nil {
			return fmt.Errorf("service %q: bind mount %q: %w", service, v.Source, err)
		}
	case "volume":
		if _, ok := volumes[v.Source]; !ok {
			return fmt.Errorf("service %q: named volume %q must be declared", service, v.Source)
		}
	case "tmpfs":
		return nil
	default:
		return fmt.Errorf("service %q: volume type %q is not allowed", service, v.Type)
	}
	return nil
}

func checkBuildContext(workDir, service string, build interface{}) error {
	if build == nil {
		return nil
	}
	switch value := build.(type) {
	case string:
		if err := checkSandboxPath(workDir, value); err != nil {
			return fmt.Errorf("service %q: build context %q: %w", service, value, err)
		}
	case map[string]interface{}:
		contextPath, ok := value["context"].(string)
		if !ok || contextPath == "" {
			return fmt.Errorf("service %q: build context is required", service)
		}
		if err := checkSandboxPath(workDir, contextPath); err != nil {
			return fmt.Errorf("service %q: build context %q: %w", service, contextPath, err)
		}
	default:
		return fmt.Errorf("service %q: invalid build configuration", service)
	}
	return nil
}

func resolveComposeFile(workDir, file string) (string, string, error) {
	if file == "" {
		return "", "", errors.New("compose file is required")
	}
	if filepath.IsAbs(file) {
		return "", "", fmt.Errorf("compose file %q must be sandbox-relative", file)
	}
	cleaned := filepath.Clean(file)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("compose file %q escapes the sandbox", file)
	}
	root, err := filepath.Abs(workDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve sandbox path: %w", err)
	}
	full := filepath.Join(root, cleaned)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("compose file %q escapes the sandbox", file)
	}
	current := root
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", "", fmt.Errorf("compose file %q: %w", file, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("compose file %q is a symlink or is below a symlink", file)
		}
	}
	info, err := os.Lstat(full)
	if err != nil {
		return "", "", fmt.Errorf("compose file %q: %w", file, err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("compose file %q is not a regular file", file)
	}
	return full, cleaned, nil
}

func checkSandboxPath(workDir, source string) error {
	if source == "" || filepath.IsAbs(source) {
		return errors.New("must be a sandbox-relative path")
	}
	root, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("resolve sandbox path: %w", err)
	}
	path := filepath.Join(root, source)
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve canonical path: %w", err)
	}
	rel, err := filepath.Rel(root, canonical)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("resolves outside the sandbox")
	}
	return nil
}

func checkNoImplicitEnvFile(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, ".env"))
	if err == nil {
		return errors.New("implicit .env is not allowed")
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("check implicit .env: %w", err)
	}
	return nil
}

func isBindSource(source string) bool {
	return source == "." || source == ".." || strings.HasPrefix(source, "."+string(filepath.Separator)) ||
		strings.HasPrefix(source, ".."+string(filepath.Separator)) || strings.Contains(source, string(filepath.Separator))
}
