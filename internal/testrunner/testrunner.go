// Package testrunner runs a project's docker compose test service against
// the sandboxed working copy.
package testrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

// outputTailBytes bounds host memory spent on untrusted test output
// (F5-MED-008). Truncation is soft: the run continues until it finishes or
// times out, only the most recent bytes are retained, and a deterministic
// marker records the drop. The retained tail stays within the bounded
// diagnostic budget.
const outputTailBytes = 256 << 10

// waitDelay bounds how long Wait may block on inherited pipes after the
// context is cancelled, so a timed-out run cannot hang the pipeline.
const waitDelay = 10 * time.Second

// Result is the outcome of one test run.
type Result struct {
	Passed bool
	// Output is the combined stdout+stderr tail of the test command,
	// bounded to outputTailBytes and marked when truncated. It is
	// intended for a local 0600 log file only — never forward it to
	// expose as-is (part C §15: no raw logs in external summaries).
	Output string
}

// ValidateProfile performs the complete read-only Compose and command-policy
// validation used before an update is allowed to create a sandbox.
func ValidateProfile(workDir string, profile config.VerificationProfile) error {
	if profile.Version != config.VerificationVersion || profile.State != config.VerificationReady || len(profile.Steps) == 0 || len(profile.Steps) > 16 {
		return errors.New("verification profile is not ready for update")
	}
	if err := config.ValidateVerificationScriptBodies(workDir, profile); err != nil {
		return err
	}
	for _, step := range profile.Steps {
		if step.TimeoutSeconds <= 0 || step.TimeoutSeconds > 7200 {
			return fmt.Errorf("verification step %q: timeout must be between 1 and 7200 seconds", step.Name)
		}
		if !validSuccessExitCodes(step.SuccessExitCodes) {
			return fmt.Errorf("verification step %q: success exit codes must be unique values between 0 and 125", step.Name)
		}
		if err := config.ValidateVerificationCommand(step.Command); err != nil {
			return fmt.Errorf("verification step %q: %w", step.Name, err)
		}
		root, composePath, err := resolveComposeFile(workDir, step.ComposeFile)
		if err != nil {
			return fmt.Errorf("verification step %q: %w", step.Name, err)
		}
		if _, err := validateCompose(root, composePath, step.Service); err != nil {
			return fmt.Errorf("verification step %q: %w", step.Name, err)
		}
	}
	return nil
}

// RunProfileWithDocker runs every explicit step in order. Optional failures
// are retained in the bounded diagnostic output; a required failure stops the
// profile and fails the gate.
func RunProfileWithDocker(ctx context.Context, docker dockerexec.Runner, workDir string, profile config.VerificationProfile) (Result, error) {
	if err := ValidateProfile(workDir, profile); err != nil {
		return Result{}, err
	}
	combined := strings.Builder{}
	for _, step := range profile.Steps {
		result, err := RunWithDocker(ctx, docker, workDir, step, time.Duration(step.TimeoutSeconds)*time.Second)
		if result.Output != "" {
			fmt.Fprintf(&combined, "[%s]\n%s", step.Name, result.Output)
			if !strings.HasSuffix(result.Output, "\n") {
				combined.WriteByte('\n')
			}
		}
		if err != nil {
			return Result{Output: combined.String()}, fmt.Errorf("verification step %q: %w", step.Name, err)
		}
		if !result.Passed && step.Required {
			return Result{Passed: false, Output: combined.String()}, nil
		}
	}
	return Result{Passed: true, Output: combined.String()}, nil
}

// Run executes one explicit verification step against workDir. The repository compose
// file is validated against a strict fail-closed allowlist (§8,
// F5-CRIT-002): unknown fields anywhere, YAML anchors/aliases, any "$"
// interpolation, build, env files, host namespaces, sockets, and weakened
// hardening are rejected before Docker is invoked. Docker Compose is then
// given a serialization of the validated model — never the repository YAML —
// so it cannot see fields the policy did not approve. The deeper sandbox
// network-egress/isolation policy belongs to part F; this is the baseline
// this package's own execution path is responsible for.
func Run(ctx context.Context, workDir string, step config.VerificationStep, timeout time.Duration) (Result, error) {
	return RunWithDocker(ctx, dockerexec.Default(), workDir, step, timeout)
}

// RunWithDocker executes one verification step through the supplied Docker boundary.
func RunWithDocker(ctx context.Context, docker dockerexec.Runner, workDir string, step config.VerificationStep, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		timeout = time.Duration(step.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 {
		return Result{}, errors.New("verification timeout must be positive")
	}
	if !composeName.MatchString(step.Service) {
		return Result{}, errors.New("test compose policy: service must be a Compose service name")
	}
	if err := config.ValidateVerificationCommand(step.Command); err != nil {
		return Result{}, fmt.Errorf("verification command policy: %w", err)
	}
	if !validSuccessExitCodes(step.SuccessExitCodes) {
		return Result{}, errors.New("verification success exit codes must be unique values between 0 and 125")
	}

	root, composePath, err := resolveComposeFile(workDir, step.ComposeFile)
	if err != nil {
		return Result{}, fmt.Errorf("test compose policy: %w", err)
	}
	normalized, err := validateCompose(root, composePath, step.Service)
	if err != nil {
		return Result{}, fmt.Errorf("test compose policy: %w", err)
	}

	// The normalized model lives outside the sandbox so it can never be
	// bind-mounted into the test container or picked up as a sandbox change.
	tmpDir, err := os.MkdirTemp("", "vuelta-compose-")
	if err != nil {
		return Result{}, fmt.Errorf("write validated compose model: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	normalizedPath := filepath.Join(tmpDir, "compose.yaml")
	if err := os.WriteFile(normalizedPath, normalized, 0o600); err != nil {
		return Result{}, fmt.Errorf("write validated compose model: %w", err)
	}
	emptyEnvPath := filepath.Join(tmpDir, "compose.env")
	if err := os.WriteFile(emptyEnvPath, nil, 0o600); err != nil {
		return Result{}, fmt.Errorf("write empty compose environment: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// --project-directory pins relative bind sources and the implicit .env
	// lookup to the sandbox root — the same base the policy validated
	// against. The normalized model contains no interpolation or host
	// inheritance, so the compose client's environment cannot change what
	// runs.
	args := []string{
		"compose", "--project-name", filepath.Base(tmpDir),
		"--project-directory", root,
		"--env-file", emptyEnvPath,
		"-f", normalizedPath,
		"run", "--rm", "--no-TTY", "--entrypoint", step.Command[0],
	}
	args = append(args, step.Service)
	args = append(args, step.Command[1:]...)

	// The client and container are resource-bounded. A separately bounded
	// `compose down` below runs even after cancellation so a timed-out client
	// cannot leave the verification container or its project volumes behind.
	commandResult, runErr := docker.Run(runCtx, dockerexec.Request{
		Args: args, Dir: root, WaitDelay: waitDelay,
		Combined: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: outputTailBytes},
	})
	result := Result{Output: string(commandResult.Combined)}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), waitDelay)
	_, cleanupErr := docker.Run(cleanupCtx, dockerexec.Request{Args: []string{
		"compose", "--project-name", filepath.Base(tmpDir), "--project-directory", root,
		"--env-file", emptyEnvPath, "-f", normalizedPath, "down", "--remove-orphans", "--volumes",
	}, Dir: root, WaitDelay: waitDelay})
	cleanupCancel()
	if cleanupErr != nil {
		return result, fmt.Errorf("verification container cleanup failed: %w", cleanupErr)
	}

	if runCtx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("verification step %q timed out after %s", step.Name, timeout)
	}
	if runErr != nil {
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) {
			return result, runErr
		}
		result.Passed = containsExitCode(step.SuccessExitCodes, exitError.ExitCode())
		return result, nil
	}
	result.Passed = containsExitCode(step.SuccessExitCodes, 0)
	return result, nil
}

var (
	digestPinned = regexp.MustCompile(`^[^\s@]+@sha256:[0-9a-f]{64}$`)
	composeName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

func containsExitCode(codes []int, wanted int) bool {
	for _, code := range codes {
		if code == wanted {
			return true
		}
	}
	return false
}

func validSuccessExitCodes(codes []int) bool {
	if len(codes) == 0 {
		return false
	}
	seen := make(map[int]bool, len(codes))
	for _, code := range codes {
		if code < 0 || code > 125 || seen[code] {
			return false
		}
		seen[code] = true
	}
	return true
}

// ValidateComposeService applies the same fail-closed Compose allowlist used
// before a verification run to one sandbox-relative compose file and service,
// without needing a full VerificationStep. Generators use it to reject their
// own output before writing it.
func ValidateComposeService(root, composeFile, service string) error {
	sandboxRoot, composePath, err := resolveComposeFile(root, composeFile)
	if err != nil {
		return err
	}
	_, err = validateCompose(sandboxRoot, composePath, service)
	return err
}

// ValidatedComposeServiceImage returns the selected service image from the
// same fail-closed model used for verification execution. Callers never need
// to parse repository-controlled Compose YAML a second time.
func ValidatedComposeServiceImage(root, composeFile, service string) (string, error) {
	sandboxRoot, composePath, err := resolveComposeFile(root, composeFile)
	if err != nil {
		return "", err
	}
	model, err := validatedComposeModel(sandboxRoot, composePath, service)
	if err != nil {
		return "", err
	}
	return model.Services[service].Image, nil
}

// validateCompose parses the compose file under the strict allowlist and
// returns the YAML serialization of the validated model. Everything Docker
// Compose will execute comes from this serialization.
func validateCompose(root, composePath, service string) ([]byte, error) {
	model, err := validatedComposeModel(root, composePath, service)
	if err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(model)
	if err != nil {
		return nil, fmt.Errorf("serialize validated compose model: %w", err)
	}
	return out, nil
}

func validatedComposeModel(root, composePath, service string) (*normalizedFile, error) {
	if err := checkNoImplicitEnvFile(root); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", composePath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", composePath, err)
	}
	if err := checkNodeSafety(&doc); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cf composeFile
	if err := dec.Decode(&cf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse %s: empty compose file", composePath)
		}
		return nil, fmt.Errorf("parse %s: %w", composePath, err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("parse %s: multiple YAML documents are not allowed", composePath)
		}
		return nil, fmt.Errorf("parse %s: invalid trailing YAML document", composePath)
	}
	model, err := buildModel(root, cf, service)
	if err != nil {
		return nil, err
	}
	return model, nil
}

// checkNodeSafety rejects YAML features the allowlist cannot reason about:
// anchors/aliases (content that is validated in one place but expanded into
// another) and any scalar containing "$" (Compose interpolation and host
// environment references). Scalar values are deliberately never echoed so a
// policy error cannot leak environment-like values.
func checkNodeSafety(node *yaml.Node) error {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return fmt.Errorf("line %d: YAML anchors and aliases are not allowed", node.Line)
	}
	if node.Kind == yaml.ScalarNode && strings.Contains(node.Value, "$") {
		return fmt.Errorf("line %d: interpolation is not allowed", node.Line)
	}
	for _, child := range node.Content {
		if err := checkNodeSafety(child); err != nil {
			return err
		}
	}
	return nil
}

// composeFile is the strict decode target: with KnownFields enabled, any
// top-level or service-level field outside this allowlist fails the parse.
// The banned forbiddenField values exist only to record presence and produce
// precise errors; their values are deliberately discarded.
type composeFile struct {
	Services map[string]composeService     `yaml:"services"`
	Volumes  map[string]composeNamedVolume `yaml:"volumes"`
	Networks map[string]composeNetwork     `yaml:"networks"`

	Include forbiddenField `yaml:"include"`
	Configs forbiddenField `yaml:"configs"`
	Secrets forbiddenField `yaml:"secrets"`
}

type composeService struct {
	Image       string                 `yaml:"image"`
	Platform    string                 `yaml:"platform,omitempty"`
	User        string                 `yaml:"user"`
	ReadOnly    bool                   `yaml:"read_only"`
	WorkingDir  string                 `yaml:"working_dir"`
	Entrypoint  composeCommand         `yaml:"entrypoint"`
	Command     composeCommand         `yaml:"command"`
	Environment composeEnvironment     `yaml:"environment"`
	Tmpfs       composeStringList      `yaml:"tmpfs"`
	CapDrop     []string               `yaml:"cap_drop"`
	SecurityOpt []string               `yaml:"security_opt"`
	CPUs        composeScalar          `yaml:"cpus"`
	MemLimit    composeScalar          `yaml:"mem_limit"`
	PidsLimit   int                    `yaml:"pids_limit"`
	Networks    composeServiceNetworks `yaml:"networks"`
	Volumes     []composeVolume        `yaml:"volumes"`
	DependsOn   composeDependencies    `yaml:"depends_on"`

	// Banned fields: presence alone is a policy violation, regardless of
	// value. Kept in the schema so the error names the field instead of
	// surfacing a generic unknown-field parse error.
	Build             forbiddenField `yaml:"build"`
	Privileged        forbiddenField `yaml:"privileged"`
	NetworkMode       forbiddenField `yaml:"network_mode"`
	Pid               forbiddenField `yaml:"pid"`
	Ipc               forbiddenField `yaml:"ipc"`
	EnvFile           forbiddenField `yaml:"env_file"`
	Devices           forbiddenField `yaml:"devices"`
	DeviceCgroupRules forbiddenField `yaml:"device_cgroup_rules"`
	CapAdd            forbiddenField `yaml:"cap_add"`
	UseAPISocket      forbiddenField `yaml:"use_api_socket"`
	Extends           forbiddenField `yaml:"extends"`
	VolumesFrom       forbiddenField `yaml:"volumes_from"`
	Configs           forbiddenField `yaml:"configs"`
	Secrets           forbiddenField `yaml:"secrets"`
	Ports             forbiddenField `yaml:"ports"`
	Expose            forbiddenField `yaml:"expose"`
}

type forbiddenField struct {
	present bool
}

func (f *forbiddenField) UnmarshalYAML(*yaml.Node) error {
	f.present = true
	return nil
}

// normalizedFile is the exact model handed to Docker Compose. It is built
// only from validated data, so Compose never sees fields, interpolation, or
// values the policy did not approve.
type normalizedFile struct {
	Services map[string]normalizedService  `yaml:"services"`
	Volumes  map[string]composeNamedVolume `yaml:"volumes,omitempty"`
	Networks map[string]normalizedNetwork  `yaml:"networks,omitempty"`
}

type normalizedService struct {
	Image       string                 `yaml:"image"`
	Platform    string                 `yaml:"platform,omitempty"`
	User        string                 `yaml:"user"`
	ReadOnly    bool                   `yaml:"read_only,omitempty"`
	WorkingDir  string                 `yaml:"working_dir,omitempty"`
	Entrypoint  composeCommand         `yaml:"entrypoint,omitempty"`
	Command     composeCommand         `yaml:"command,omitempty"`
	Environment composeEnvironment     `yaml:"environment,omitempty"`
	Tmpfs       composeStringList      `yaml:"tmpfs,omitempty"`
	CapDrop     []string               `yaml:"cap_drop"`
	SecurityOpt []string               `yaml:"security_opt"`
	CPUs        composeScalar          `yaml:"cpus"`
	MemLimit    composeScalar          `yaml:"mem_limit"`
	PidsLimit   int                    `yaml:"pids_limit"`
	Networks    composeServiceNetworks `yaml:"networks"`
	Volumes     []composeVolume        `yaml:"volumes,omitempty"`
	DependsOn   composeDependencies    `yaml:"depends_on,omitempty"`
}

type normalizedNetwork struct {
	Internal bool `yaml:"internal"`
}

func buildModel(root string, cf composeFile, service string) (*normalizedFile, error) {
	if cf.Include.present {
		return nil, errors.New("top-level include is not allowed")
	}
	if cf.Configs.present || cf.Secrets.present {
		return nil, errors.New("top-level configs and secrets are not allowed")
	}
	if len(cf.Services) == 0 {
		return nil, errors.New("no services defined")
	}
	for name := range cf.Services {
		if !composeName.MatchString(name) {
			return nil, errors.New("service name is not allowed")
		}
	}
	if _, ok := cf.Services[service]; !ok {
		return nil, fmt.Errorf("service %q not found", service)
	}
	for _, name := range sortedNetworkNames(cf.Networks) {
		if !cf.Networks[name].Internal {
			return nil, fmt.Errorf("network %q must be an unnamed internal test network", name)
		}
	}

	model := &normalizedFile{Services: make(map[string]normalizedService, len(cf.Services))}
	if len(cf.Volumes) > 0 {
		model.Volumes = cf.Volumes
	}
	if len(cf.Networks) > 0 {
		model.Networks = make(map[string]normalizedNetwork, len(cf.Networks))
		for name := range cf.Networks {
			model.Networks[name] = normalizedNetwork{Internal: true}
		}
	}

	// Every service in the file is validated and serialized: `compose run`
	// starts dependencies, and a fail-closed policy has no notion of an
	// unchecked bystander service.
	for _, name := range sortedServiceNames(cf.Services) {
		normalized, err := checkService(root, cf, name, cf.Services[name])
		if err != nil {
			return nil, err
		}
		if name == service {
			// The CLI supplies an explicit --entrypoint and argv. An empty
			// command prevents an image or service CMD from being inherited
			// when the configured argv contains only the executable.
			normalized.Entrypoint = composeCommand{}
			normalized.Command = composeCommand{args: []string{}}
		}
		model.Services[name] = normalized
	}
	return model, nil
}

func checkService(root string, cf composeFile, name string, svc composeService) (normalizedService, error) {
	var zero normalizedService

	for _, banned := range []struct {
		field forbiddenField
		msg   string
	}{
		{svc.Build, "build is not allowed; use a digest-pinned prebuilt image"},
		{svc.Privileged, "privileged is not allowed"},
		{svc.NetworkMode, "network_mode is not allowed"},
		{svc.Pid, "pid is not allowed"},
		{svc.Ipc, "ipc is not allowed"},
		{svc.EnvFile, "env_file is not allowed"},
		{svc.Devices, "devices are not allowed"},
		{svc.DeviceCgroupRules, "devices are not allowed"},
		{svc.CapAdd, "cap_add is not allowed"},
		{svc.UseAPISocket, "use_api_socket is not allowed"},
		{svc.Extends, "extends is not allowed"},
		{svc.VolumesFrom, "volumes_from is not allowed"},
		{svc.Configs, "configs are not allowed"},
		{svc.Secrets, "secrets are not allowed"},
		{svc.Ports, "ports are not allowed"},
		{svc.Expose, "expose is not allowed"},
	} {
		if banned.field.present {
			return zero, fmt.Errorf("service %q: %s", name, banned.msg)
		}
	}

	var volumes []composeVolume
	for _, v := range svc.Volumes {
		checked, err := checkVolume(root, cf.Volumes, name, v)
		if err != nil {
			return zero, err
		}
		volumes = append(volumes, checked)
	}

	if svc.Image == "" {
		return zero, fmt.Errorf("service %q: a digest-pinned prebuilt image is required", name)
	}
	if !digestPinned.MatchString(svc.Image) {
		return zero, fmt.Errorf("service %q: image %q must be pinned by digest", name, svc.Image)
	}
	if svc.Platform != "" && svc.Platform != "linux/amd64" && svc.Platform != "linux/arm64" {
		return zero, fmt.Errorf("service %q: platform must be linux/amd64 or linux/arm64", name)
	}
	if !isExplicitNonRootUser(svc.User) {
		return zero, fmt.Errorf("service %q: user must be an explicit non-root UID", name)
	}
	if !svc.ReadOnly {
		return zero, fmt.Errorf("service %q: read_only must be true", name)
	}
	if !hasAllCapabilityDrop(svc.CapDrop) {
		return zero, fmt.Errorf("service %q: cap_drop must include ALL", name)
	}
	for _, opt := range svc.SecurityOpt {
		if opt != "no-new-privileges" && opt != "no-new-privileges:true" {
			return zero, fmt.Errorf("service %q: security_opt %q is not allowed", name, opt)
		}
	}
	if !hasNoNewPrivileges(svc.SecurityOpt) {
		return zero, fmt.Errorf("service %q: security_opt must include no-new-privileges", name)
	}
	if !isPositiveCPU(svc.CPUs) || !isPositiveMemoryLimit(svc.MemLimit) || svc.PidsLimit <= 0 {
		return zero, fmt.Errorf("service %q: cpus, mem_limit, and pids_limit are required", name)
	}
	if err := checkInternalNetworks(cf.Networks, name, svc.Networks); err != nil {
		return zero, err
	}
	for _, dependency := range svc.DependsOn {
		if _, ok := cf.Services[dependency]; !ok {
			return zero, fmt.Errorf("service %q: dependency %q not found", name, dependency)
		}
	}

	return normalizedService{
		Image:       svc.Image,
		Platform:    svc.Platform,
		User:        svc.User,
		ReadOnly:    svc.ReadOnly,
		WorkingDir:  svc.WorkingDir,
		Entrypoint:  svc.Entrypoint,
		Command:     svc.Command,
		Environment: svc.Environment,
		Tmpfs:       svc.Tmpfs,
		CapDrop:     svc.CapDrop,
		SecurityOpt: svc.SecurityOpt,
		CPUs:        svc.CPUs,
		MemLimit:    svc.MemLimit,
		PidsLimit:   svc.PidsLimit,
		Networks:    svc.Networks,
		Volumes:     volumes,
		DependsOn:   svc.DependsOn,
	}, nil
}

func sortedServiceNames(services map[string]composeService) []string {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedNetworkNames(networks map[string]composeNetwork) []string {
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// composeCommand accepts Compose's string and list forms for command and
// entrypoint and re-serializes the same form.
type composeCommand struct {
	shell string
	args  []string
}

func (c *composeCommand) UnmarshalYAML(value *yaml.Node) error {
	switch {
	case value.Kind == yaml.ScalarNode && value.Tag == "!!null":
		return nil
	case value.Kind == yaml.ScalarNode:
		c.shell = value.Value
		return nil
	case value.Kind == yaml.SequenceNode:
		c.args = []string{}
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				return errors.New("command entries must be strings")
			}
			c.args = append(c.args, item.Value)
		}
		return nil
	}
	return errors.New("command must be a string or a list of strings")
}

func (c composeCommand) MarshalYAML() (interface{}, error) {
	if c.args != nil {
		return c.args, nil
	}
	return c.shell, nil
}

func (c composeCommand) IsZero() bool { return c.shell == "" && c.args == nil }

// composeStringList accepts a scalar or a list of scalars (tmpfs).
type composeStringList []string

func (l *composeStringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Tag == "!!null" {
			return nil
		}
		*l = composeStringList{value.Value}
		return nil
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				return errors.New("entries must be strings")
			}
			*l = append(*l, item.Value)
		}
		return nil
	}
	return errors.New("must be a string or a list of strings")
}

// composeEnvironment accepts only concrete values: list entries must be
// explicit KEY=value pairs and map values must be non-null scalars. Bare
// keys (host inheritance) fail closed; "$" interpolation is already
// rejected document-wide before decoding.
type composeEnvironment struct {
	list []string
	kv   map[string]string
}

func (e *composeEnvironment) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode || !strings.Contains(item.Value, "=") || strings.HasPrefix(item.Value, "=") {
				return errors.New("environment must use explicit KEY=value entries")
			}
			e.list = append(e.list, item.Value)
		}
		return nil
	case yaml.MappingNode:
		e.kv = make(map[string]string, len(value.Content)/2)
		for i := 0; i < len(value.Content); i += 2 {
			key, val := value.Content[i], value.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Value == "" {
				return errors.New("environment keys must be non-empty strings")
			}
			if val.Kind != yaml.ScalarNode || val.Tag == "!!null" {
				return fmt.Errorf("environment %q must have a concrete scalar value", key.Value)
			}
			e.kv[key.Value] = val.Value
		}
		return nil
	case yaml.ScalarNode:
		if value.Tag == "!!null" {
			return nil
		}
	}
	return errors.New("invalid environment configuration")
}

func (e composeEnvironment) MarshalYAML() (interface{}, error) {
	if e.list != nil {
		return e.list, nil
	}
	return e.kv, nil
}

func (e composeEnvironment) IsZero() bool { return e.list == nil && len(e.kv) == 0 }

// composeScalar accepts any non-null YAML scalar (quoted or bare number) and
// serializes its literal text as a string.
type composeScalar string

func (s *composeScalar) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
		return errors.New("must be a scalar value")
	}
	*s = composeScalar(value.Value)
	return nil
}

// composeServiceNetworks accepts the list form and the map form with no
// per-network options: aliases, static addresses, and priorities widen the
// runner's authority and fail closed.
type composeServiceNetworks []string

func (n *composeServiceNetworks) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode || item.Value == "" || item.Tag == "!!null" {
				return errors.New("invalid network entry")
			}
			*n = append(*n, item.Value)
		}
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(value.Content); i += 2 {
			key, val := value.Content[i], value.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Value == "" {
				return errors.New("invalid network entry")
			}
			if val.Tag != "!!null" {
				return errors.New("per-network service options are not allowed")
			}
			*n = append(*n, key.Value)
		}
		sort.Strings(*n)
		return nil
	}
	return errors.New("invalid networks configuration")
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
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(value.Content); i += 2 {
			name, options := value.Content[i], value.Content[i+1]
			if name.Kind != yaml.ScalarNode || name.Value == "" {
				return errors.New("depends_on keys must be service names")
			}
			if err := checkDependencyOptions(options); err != nil {
				return fmt.Errorf("depends_on %q: %w", name.Value, err)
			}
			*d = append(*d, name.Value)
		}
		return nil
	}
	return errors.New("depends_on must be a list or map")
}

// checkDependencyOptions allows only the default start condition: the
// normalized model serializes dependencies in list form, which Compose
// treats as service_started, so any other condition would silently change
// semantics (and healthcheck-based conditions are unusable here anyway,
// because healthcheck is outside the allowlist).
func checkDependencyOptions(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return errors.New("options must be a mapping")
	}
	for i := 0; i < len(value.Content); i += 2 {
		key, val := value.Content[i], value.Content[i+1]
		if key.Value != "condition" || val.Kind != yaml.ScalarNode || val.Value != "service_started" {
			return errors.New("only condition service_started is allowed")
		}
	}
	return nil
}

// composeVolume accepts short syntax with at most a ro/rw option and long
// syntax restricted to type, source, target, and read_only. It always
// re-serializes in long syntax.
type composeVolume struct {
	Type     string
	Source   string
	Target   string
	ReadOnly bool
}

func (v *composeVolume) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		parts := strings.Split(value.Value, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid short volume syntax %q", value.Value)
		}
		v.Source, v.Target = parts[0], parts[1]
		if len(parts) == 3 {
			switch parts[2] {
			case "ro":
				v.ReadOnly = true
			case "rw":
			default:
				return fmt.Errorf("volume option %q is not allowed", parts[2])
			}
		}
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
	for i := 0; i < len(value.Content); i += 2 {
		key, val := value.Content[i], value.Content[i+1]
		switch key.Value {
		case "type", "source", "target":
			if val.Kind != yaml.ScalarNode || val.Tag == "!!null" {
				return fmt.Errorf("volume %s must be a string", key.Value)
			}
			switch key.Value {
			case "type":
				v.Type = val.Value
			case "source":
				v.Source = val.Value
			case "target":
				v.Target = val.Value
			}
		case "read_only":
			if err := val.Decode(&v.ReadOnly); err != nil {
				return err
			}
		default:
			return fmt.Errorf("volume field %q is not allowed", key.Value)
		}
	}
	if v.Type == "" {
		return errors.New("long volume syntax requires type")
	}
	return nil
}

func (v composeVolume) MarshalYAML() (interface{}, error) {
	type longVolume struct {
		Type     string `yaml:"type"`
		Source   string `yaml:"source,omitempty"`
		Target   string `yaml:"target"`
		ReadOnly bool   `yaml:"read_only,omitempty"`
	}
	return longVolume(v), nil
}

// composeNamedVolume accepts only an empty declaration: local driver, no
// name, no options.
type composeNamedVolume struct{}

func (v *composeNamedVolume) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.MappingNode && len(value.Content) == 0 {
		return nil
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		return nil
	}
	return errors.New("named volumes must be declared empty: local driver, no name or options")
}

func (v composeNamedVolume) MarshalYAML() (interface{}, error) {
	return map[string]string{}, nil
}

// composeNetwork allows only the internal marker; every other network
// option is outside the allowlist and fails the strict parse.
type composeNetwork struct {
	Internal bool `yaml:"internal"`
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

func isExplicitNonRootUser(user string) bool {
	parts := strings.Split(user, ":")
	if len(parts) == 0 || len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil || value == 0 {
			return false
		}
	}
	return true
}

func isPositiveCPU(value composeScalar) bool {
	parsed, err := strconv.ParseFloat(string(value), 64)
	return err == nil && parsed > 0 && !math.IsInf(parsed, 0) && !math.IsNaN(parsed)
}

var positiveMemoryLimit = regexp.MustCompile(`(?i)^[1-9][0-9]*(?:\.[0-9]+)?(?:[kmgtpe](?:i?b)?|b)?$`)

func isPositiveMemoryLimit(value composeScalar) bool {
	return positiveMemoryLimit.MatchString(string(value))
}

func checkInternalNetworks(networks map[string]composeNetwork, service string, names composeServiceNetworks) error {
	if len(names) == 0 {
		return fmt.Errorf("service %q: an explicit internal test network is required", service)
	}
	for _, name := range names {
		network, ok := networks[name]
		if !ok || !network.Internal {
			return fmt.Errorf("service %q: network %q must be declared internal", service, name)
		}
	}
	return nil
}

func checkVolume(root string, volumes map[string]composeNamedVolume, service string, v composeVolume) (composeVolume, error) {
	if v.Target == "" || !strings.HasPrefix(v.Target, "/") {
		return v, fmt.Errorf("service %q: volume target must be an absolute container path", service)
	}
	switch v.Type {
	case "bind":
		if strings.Contains(v.Source, "docker.sock") {
			return v, fmt.Errorf("service %q: docker socket mount is not allowed", service)
		}
		if err := checkSandboxPath(root, v.Source); err != nil {
			return v, fmt.Errorf("service %q: bind mount %q: %w", service, v.Source, err)
		}
		v.Source = normalizeBindSource(v.Source)
	case "volume":
		if v.Source == "" {
			return v, fmt.Errorf("service %q: named volume source is required", service)
		}
		if _, ok := volumes[v.Source]; !ok {
			return v, fmt.Errorf("service %q: named volume %q must be declared", service, v.Source)
		}
	case "tmpfs":
		if v.Source != "" {
			return v, fmt.Errorf("service %q: tmpfs volumes must not set source", service)
		}
	default:
		return v, fmt.Errorf("service %q: volume type %q is not allowed", service, v.Type)
	}
	return v, nil
}

// normalizeBindSource pins the serialized source to an explicitly relative
// form so Compose resolves it against --project-directory (the sandbox
// root), the same base checkSandboxPath validated.
func normalizeBindSource(source string) string {
	cleaned := filepath.ToSlash(filepath.Clean(source))
	if cleaned == "." {
		return "./"
	}
	return "./" + cleaned
}

// resolveComposeFile validates the profile's compose path and returns the
// absolute sandbox root and the absolute, symlink-free compose file path.
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
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve sandbox path: %w", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return "", "", fmt.Errorf("inspect sandbox path: %w", err)
	}
	if !rootInfo.IsDir() {
		return "", "", errors.New("sandbox path is not a directory")
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
	return root, full, nil
}

func checkSandboxPath(workDir, source string) error {
	if source == "" || filepath.IsAbs(source) {
		return errors.New("must be a sandbox-relative path")
	}
	root, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("resolve sandbox path: %w", err)
	}
	cleaned := filepath.Clean(source)
	path := filepath.Join(root, cleaned)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("resolves outside the sandbox")
	}
	current := root
	var info os.FileInfo
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err = os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect sandbox path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink bind sources are not allowed")
		}
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return errors.New("must resolve to a regular file or directory; sockets and devices are not allowed")
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
