package configinit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/gitpath"
	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"gopkg.in/yaml.v3"
)

var (
	composeNames = []string{
		"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml",
		"compose.verify.yaml", "compose.verify.yml",
	}
	dockerNames = []string{"Dockerfile", "dockerfile"}
	// fromPattern captures the image reference and, if present, the "AS name"
	// build-stage alias: a later FROM referencing that alias is an internal
	// build stage, not an external image reference.
	fromPattern = regexp.MustCompile(`(?mi)^\s*FROM\s+(?:--[^\s]+\s+)*(\S+)(?:\s+[Aa][Ss]\s+(\S+))?`)
)

// Discovery contains only values found in allowlisted, project-root files or
// optional Git metadata explicitly associated with Root.
type Discovery struct {
	Root                   string
	Stacks                 []string
	PackageManagers        map[string][]string
	ComposeFiles           []string
	Services               map[string][]string
	Branches               []string
	Remotes                []string
	DockerFiles            []string
	RuntimeImages          []string
	VerificationCandidates []config.VerificationStep
}

// Input supplies choices that could not be made deterministically. Repeated
// fields correspond to repeatable CLI flags.
type Input struct {
	Name, Stack, PackageManager, Branch, Remote string
	AllowedPaths, DockerFiles, RuntimeImages    []string
	VerificationNames                           []string
	ScanOnly                                    bool
	// Repair admits managers by their vulnerability-repair contract instead of
	// a candidate scanner. It is only for the ephemeral workspace of `fix`.
	Repair bool
}

// MissingValueError identifies a required flag when detection is ambiguous or
// cannot determine a safe value.
type MissingValueError struct {
	Flag    string
	Options []string
}

func (e *MissingValueError) Error() string {
	if len(e.Options) == 0 {
		return fmt.Sprintf("%s is required", e.Flag)
	}
	return fmt.Sprintf("%s is required; detected: %s", e.Flag, strings.Join(e.Options, ", "))
}

// Detect inspects only allowlisted files immediately inside selectedRoot.
func Detect(selectedRoot string) (Discovery, error) {
	root, err := filepath.Abs(selectedRoot)
	if err != nil {
		return Discovery{}, fmt.Errorf("resolve project path: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Discovery{}, fmt.Errorf("resolve project path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return Discovery{}, fmt.Errorf("project path %s is not a directory", root)
	}
	rootFiles, err := regularRootFiles(root, dockerNames, composeNames)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{Root: root, PackageManagers: make(map[string][]string), Services: make(map[string][]string)}
	detectedAdapters, err := catalog.Discover(root)
	if err != nil {
		return Discovery{}, err
	}
	for _, adapter := range detectedAdapters {
		d.addManager(adapter.Key().Stack, adapter.Key().PackageManager)
	}
	for _, name := range dockerNames {
		if rootFiles[name] {
			d.DockerFiles = append(d.DockerFiles, name)
			images, err := dockerRuntimeImages(filepath.Join(root, name))
			if err != nil {
				return Discovery{}, err
			}
			d.RuntimeImages = append(d.RuntimeImages, images...)
		}
	}
	hasDockerfile := len(d.DockerFiles) > 0
	for _, name := range composeNames {
		if !rootFiles[name] {
			continue
		}
		d.ComposeFiles = append(d.ComposeFiles, name)
		services, err := composeServices(filepath.Join(root, name))
		if err != nil {
			return Discovery{}, fmt.Errorf("read compose file %s: %w", name, err)
		}
		d.Services[name] = services
		images, err := composeRuntimeImages(filepath.Join(root, name))
		if err != nil {
			return Discovery{}, fmt.Errorf("read compose file %s images: %w", name, err)
		}
		if len(images) > 0 {
			d.DockerFiles = append(d.DockerFiles, name)
			d.RuntimeImages = append(d.RuntimeImages, images...)
		}
	}
	if hasDockerfile || (len(d.Stacks) == 0 && len(d.DockerFiles) > 0) {
		d.Stacks = append(d.Stacks, config.StackDocker)
	}
	d.VerificationCandidates, err = verificationCandidates(root, d)
	if err != nil {
		return Discovery{}, err
	}
	d.Branches = gitValues(root, "branch", "--show-current")
	d.Remotes = gitValues(root, "remote")
	sort.Strings(d.Stacks)
	for stack := range d.PackageManagers {
		sort.Strings(d.PackageManagers[stack])
	}
	d.RuntimeImages = uniqueSorted(d.RuntimeImages)
	return d, nil
}

// regularRootFiles enumerates the directory once and records only allowlisted
// regular files under their exact stored names. Probing multiple case variants
// with Lstat makes one Dockerfile appear under every variant on
// case-insensitive systems.
func regularRootFiles(root string, allowlists ...[]string) (map[string]bool, error) {
	allowed := make(map[string]bool)
	for _, names := range allowlists {
		for _, name := range names {
			allowed[name] = true
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read project root: %w", err)
	}
	files := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect project root entry %s: %w", entry.Name(), err)
		}
		if info.Mode().IsRegular() {
			files[entry.Name()] = true
		}
	}
	return files, nil
}

func (d *Discovery) addManager(stack, manager string) {
	if len(d.PackageManagers[stack]) == 0 {
		d.Stacks = append(d.Stacks, stack)
	}
	d.PackageManagers[stack] = append(d.PackageManagers[stack], manager)
}

func regular(root, name string) bool {
	info, err := os.Lstat(filepath.Join(root, name))
	return err == nil && info.Mode().IsRegular()
}

// dockerRuntimeImages records every external base-image reference in a
// Dockerfile as intent: an exact digest pin, or a bare tag resolved at scan
// time. "scratch" and references to an earlier build stage's "AS" alias are
// not external images and are excluded.
func dockerRuntimeImages(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Dockerfile: %w", err)
	}
	stageNames := make(map[string]bool)
	var images []string
	for _, match := range fromPattern.FindAllStringSubmatch(string(data), -1) {
		reference := match[1]
		if !stageNames[strings.ToLower(reference)] && !strings.EqualFold(reference, "scratch") {
			images = append(images, reference)
		}
		if len(match) > 2 && match[2] != "" {
			stageNames[strings.ToLower(match[2])] = true
		}
	}
	return images, nil
}

func composeServices(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	services := make([]string, 0, len(document.Services))
	for name := range document.Services {
		services = append(services, name)
	}
	sort.Strings(services)
	return services, nil
}

func composeRuntimeImages(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	images := make([]string, 0, len(document.Services))
	for _, service := range document.Services {
		if service.Image != "" {
			images = append(images, service.Image)
		}
	}
	return uniqueSorted(images), nil
}

var verificationFactories = []string{"test", "lint", "typecheck", "check", "build"}

func verificationCandidates(root string, discovery Discovery) ([]config.VerificationStep, error) {
	var candidates []config.VerificationStep
	scripts, err := packageScripts(root)
	if err != nil {
		return nil, err
	}
	for _, composeFile := range discovery.ComposeFiles {
		for _, service := range discovery.Services[composeFile] {
			for _, factory := range verificationFactories {
				body, ok := scripts[factory]
				if !ok || !safePackageScript(body) || !verificationService(service, factory) {
					continue
				}
				for _, manager := range discovery.PackageManagers[config.StackNode] {
					registry, err := catalog.New()
					if err != nil {
						return nil, err
					}
					adapter, err := registry.Lookup(config.StackNode, manager)
					if err != nil {
						return nil, err
					}
					command := adapter.(ecosystem.VerificationProvider).VerificationCommand(factory)
					candidates = append(candidates, newVerificationCandidate(factory, composeFile, service, command))
				}
			}
		}
	}
	if len(candidates) == 0 {
		for _, composeFile := range discovery.ComposeFiles {
			steps, detectErr := composeCommandCandidates(filepath.Join(root, composeFile), composeFile)
			if detectErr != nil {
				return nil, fmt.Errorf("read verification metadata from %s: %w", composeFile, detectErr)
			}
			candidates = append(candidates, steps...)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return candidates, nil
}

func packageScripts(root string) (map[string]string, error) {
	if !regular(root, "package.json") {
		return map[string]string{}, nil
	}
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("read package.json verification metadata: %w", err)
	}
	var document struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse package.json verification metadata: %w", err)
	}
	return document.Scripts, nil
}

func safePackageScript(body string) bool {
	if body == "" || strings.ContainsAny(body, "\r\n;&|`$><") {
		return false
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "--watch") || strings.Contains(lower, " -w") {
		return false
	}
	unsafeWord := regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(dev|watch|serve|server|start|preview|interactive)([^a-z0-9_-]|$)`)
	return !unsafeWord.MatchString(body)
}

func verificationService(service, factory string) bool {
	if service == factory {
		return true
	}
	return service == "verify" || service == "verification" || service == "ci"
}

func newVerificationCandidate(factory, composeFile, service string, command []string) config.VerificationStep {
	fileID := strings.TrimSuffix(strings.TrimSuffix(composeFile, filepath.Ext(composeFile)), filepath.Ext(strings.TrimSuffix(composeFile, filepath.Ext(composeFile))))
	name := factory + "-" + strings.ReplaceAll(fileID, ".", "-") + "-" + service
	return config.VerificationStep{
		Name: name, ComposeFile: composeFile, Service: service, Command: command,
		TimeoutSeconds: 900, Required: true, SuccessExitCodes: []int{0},
	}
}

func composeCommandCandidates(path, composeFile string) ([]config.VerificationStep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Services map[string]struct {
			Command yaml.Node `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	var candidates []config.VerificationStep
	for _, factory := range verificationFactories {
		service, ok := document.Services[factory]
		if !ok || service.Command.Kind != yaml.SequenceNode {
			continue
		}
		command := make([]string, 0, len(service.Command.Content))
		valid := true
		for _, item := range service.Command.Content {
			if item.Kind != yaml.ScalarNode || item.Tag == "!!null" {
				valid = false
				break
			}
			command = append(command, item.Value)
		}
		if !valid || config.ValidateVerificationCommand(command) != nil {
			continue
		}
		candidates = append(candidates, newVerificationCandidate(factory, composeFile, factory, command))
	}
	return candidates, nil
}

func gitValues(root string, args ...string) []string {
	out, err := gitexec.Output(context.Background(), root, args...)
	if err != nil {
		return nil
	}
	return uniqueSorted(strings.Fields(string(out)))
}

// NewConfig returns the empty, validated container created by config init.
// It deliberately contains no workspace and no credentials.
func NewConfig() *config.Config {
	return &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		VulnScan: config.VulnScanConfig{
			DependencySource: "trivy", Image: trivyImage,
			FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24,
		},
		Update: config.UpdateConfig{
			MinReleaseAgeDays: 14,
			SnapshotTTLHours:  24,
			Egress: config.EgressConfig{
				Network: "vuelta-cli-update-egress", ProxyContainer: "vuelta-cli-egress-proxy",
				ProxyURL: "http://vuelta-cli-egress-proxy:3128",
			},
		},
		Workspaces: []config.Workspace{},
		Git:        config.GitConfig{PushMode: "review_branch"},
	}
}

// Build preserves the original wizard API for callers that need a complete
// one-workspace config. New onboarding uses NewConfig followed by
// BuildWorkspace and a yaml.Node edit.
func (d Discovery) Build(input Input) (*config.Config, error) {
	ws, err := d.BuildWorkspace(input)
	if err != nil {
		return nil, err
	}
	cfg := NewConfig()
	cfg.Workspaces = []config.Workspace{ws}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generated configuration is invalid: %w", err)
	}
	return cfg, nil
}

// BuildWorkspace returns a workspace only when every required selection is
// explicit or uniquely detected.
func (d Discovery) BuildWorkspace(input Input) (config.Workspace, error) {
	stack, err := choose("--stack", input.Stack, d.Stacks)
	if err != nil {
		return config.Workspace{}, err
	}
	if !contains(d.Stacks, stack) {
		return config.Workspace{}, fmt.Errorf("--stack %q was not detected in the selected project", stack)
	}
	manager := ""
	if stack != config.StackDocker {
		manager, err = choose("--package-manager", input.PackageManager, d.PackageManagers[stack])
		if err != nil {
			return config.Workspace{}, err
		}
		if !contains(d.PackageManagers[stack], manager) {
			return config.Workspace{}, fmt.Errorf("--package-manager %q was not detected for stack %q", manager, stack)
		}
		validate := toolchain.ValidateManagerSupport
		if input.Repair {
			validate = toolchain.ValidateRepairSupport
		}
		if err := validate(stack, manager); err != nil {
			return config.Workspace{}, err
		}
	}
	verification, err := d.buildVerification(input, stack, manager)
	if err != nil {
		return config.Workspace{}, err
	}
	if verification.State == config.VerificationReady {
		verification, err = config.PinVerificationScriptBodies(d.Root, verification)
		if err != nil {
			return config.Workspace{}, fmt.Errorf("pin verification package scripts: %w", err)
		}
	}
	branch, err := chooseOptional("--branch", input.Branch, d.Branches)
	if err != nil {
		return config.Workspace{}, err
	}
	remote, err := chooseOptional("--remote", input.Remote, d.Remotes)
	if err != nil {
		return config.Workspace{}, err
	}

	allowed := input.AllowedPaths
	if len(allowed) == 0 {
		allowed = defaultAllowedPaths(stack, manager, d.DockerFiles)
	}
	if len(allowed) == 0 {
		return config.Workspace{}, &MissingValueError{Flag: "--allow-path"}
	}
	for _, path := range allowed {
		if err := gitpath.ValidatePattern(path); err != nil {
			return config.Workspace{}, fmt.Errorf("--allow-path %q is invalid: %w", path, err)
		}
	}
	name := input.Name
	if name == "" {
		name = filepath.Base(d.Root)
	}
	ws := config.Workspace{Name: name, Path: d.Root, Stack: stack, PackageManager: manager, Branch: branch, Remote: remote,
		AllowedChangedPaths: uniqueSorted(allowed), Verification: verification}
	if stack == config.StackDocker {
		files := input.DockerFiles
		if len(files) == 0 {
			files = d.DockerFiles
		}
		for _, file := range files {
			if !contains(d.DockerFiles, file) {
				return config.Workspace{}, fmt.Errorf("--docker-file %q is not a detected project-root Dockerfile", file)
			}
		}
		images := input.RuntimeImages
		if len(images) == 0 {
			images = d.RuntimeImages
		}
		ws.DockerImages = &config.DockerImagesSpec{Files: uniqueSorted(files), RuntimeImages: uniqueSorted(images), Platforms: []string{"linux/amd64"}}
	}
	cfg := NewConfig()
	cfg.Workspaces = []config.Workspace{ws}
	if err := cfg.Validate(); err != nil {
		return config.Workspace{}, fmt.Errorf("generated workspace is invalid: %w", err)
	}
	if ws.Verification.State == config.VerificationReady {
		if err := testrunner.ValidateProfile(ws.Path, ws.Verification); err != nil {
			return config.Workspace{}, fmt.Errorf("generated verification profile is not allowed by the Compose policy: %w", err)
		}
	}
	return ws, nil
}

func (d Discovery) buildVerification(input Input, stack, manager string) (config.VerificationProfile, error) {
	if adapterScanOnly(stack, manager) {
		if len(input.VerificationNames) != 0 {
			return config.VerificationProfile{}, fmt.Errorf("%s/%s has no safe mutation contract and cannot use --verification; register it as scan-only", stack, manager)
		}
		return config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly}, nil
	}
	if input.ScanOnly {
		if len(input.VerificationNames) != 0 {
			return config.VerificationProfile{}, errors.New("--scan-only cannot be combined with --verification")
		}
		return config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly}, nil
	}
	candidates := d.verificationCandidatesForManager(stack, manager)
	names := append([]string(nil), input.VerificationNames...)
	if len(names) == 0 {
		switch len(candidates) {
		case 0:
			return config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly}, nil
		case 1:
			names = []string{candidates[0].Name}
		default:
			options := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				options = append(options, candidate.Name)
			}
			return config.VerificationProfile{}, &MissingValueError{Flag: "--verification", Options: options}
		}
	}
	selected := make([]config.VerificationStep, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			return config.VerificationProfile{}, fmt.Errorf("--verification %q was selected more than once", name)
		}
		seen[name] = true
		found := false
		for _, candidate := range candidates {
			if candidate.Name == name {
				selected = append(selected, candidate)
				found = true
				break
			}
		}
		if !found {
			return config.VerificationProfile{}, fmt.Errorf("--verification %q is not a declarative verification candidate", name)
		}
	}
	return config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationReady, Steps: selected}, nil
}

// BuildReadyVerification selects and validates an explicit ready profile for
// an existing project workspace. It uses the same declarative candidates and
// selection rules as onboarding, but fails instead of returning scan_only
// when the project has no verification service to approve.
func (d Discovery) BuildReadyVerification(workspace config.Workspace, names []string) (config.VerificationProfile, error) {
	if workspace.Verification.State != config.VerificationScanOnly && workspace.Verification.State != config.VerificationReady {
		return config.VerificationProfile{}, errors.New("project verification profile must be scan_only or ready")
	}
	if d.Root != workspace.Path {
		return config.VerificationProfile{}, errors.New("verification discovery root does not match the project config root")
	}
	profile := workspace.Verification
	if workspace.Verification.State == config.VerificationScanOnly || len(names) != 0 {
		var err error
		profile, err = d.buildVerification(Input{VerificationNames: names}, workspace.Stack, workspace.PackageManager)
		if err != nil {
			return config.VerificationProfile{}, err
		}
	}
	if profile.State != config.VerificationReady {
		return config.VerificationProfile{}, errors.New("no Compose file declares a verification service; run 'vuelta project verify init' first")
	}
	pinned, err := config.PinVerificationScriptBodies(workspace.Path, profile)
	if err != nil {
		return config.VerificationProfile{}, fmt.Errorf("pin verification package scripts: %w", err)
	}
	profile = pinned
	workspace.Verification = profile
	if err := config.ValidateWorkspace(workspace); err != nil {
		return config.VerificationProfile{}, fmt.Errorf("validate approved project workspace: %w", err)
	}
	if err := testrunner.ValidateProfile(workspace.Path, profile); err != nil {
		return config.VerificationProfile{}, fmt.Errorf("verification profile is not allowed by the Compose policy: %w", err)
	}
	return profile, nil
}

func (d Discovery) verificationCandidatesForManager(stack, manager string) []config.VerificationStep {
	candidates := make([]config.VerificationStep, 0, len(d.VerificationCandidates))
	for _, candidate := range d.VerificationCandidates {
		if len(candidate.Command) > 0 {
			if registry, err := catalog.New(); err == nil {
				if _, lookupErr := registry.Lookup(stack, candidate.Command[0]); lookupErr == nil && candidate.Command[0] != manager {
					continue
				}
			}
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func adapterScanOnly(stack, manager string) bool {
	registry, err := catalog.New()
	if err != nil {
		return false
	}
	adapter, err := registry.Lookup(stack, manager)
	if err != nil {
		return false
	}
	_, mutable := adapter.(ecosystem.MutationProvider)
	return !mutable && adapter.Metadata().UnsupportedReason == ""
}

func choose(flag, supplied string, options []string) (string, error) {
	if supplied != "" {
		return supplied, nil
	}
	if len(options) == 1 {
		return options[0], nil
	}
	return "", &MissingValueError{Flag: flag, Options: options}
}

func chooseOptional(flag, supplied string, options []string) (string, error) {
	if supplied != "" {
		return supplied, nil
	}
	switch len(options) {
	case 0:
		return "", nil
	case 1:
		return options[0], nil
	default:
		return "", &MissingValueError{Flag: flag, Options: options}
	}
}

func defaultAllowedPaths(stack, manager string, dockerFiles []string) []string {
	if stack == config.StackDocker {
		return dockerFiles
	}
	registry, err := catalog.New()
	if err != nil {
		return nil
	}
	adapter, err := registry.Lookup(stack, manager)
	if err != nil {
		return nil
	}
	policy, ok := adapter.(ecosystem.ChangePolicy)
	if !ok {
		return nil
	}
	return policy.AllowedChangedPaths()
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// Write plans and atomically applies creation or replacement of a config.
func Write(cfg *config.Config, path string, replace bool) error {
	plan, err := PlanConfigWrite(cfg, path, replace)
	if err != nil {
		return err
	}
	return plan.Apply(path)
}

// IsTerminal reports whether r is an interactive terminal without reading it.
func IsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
