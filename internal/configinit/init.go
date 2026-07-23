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
	fromPattern = regexp.MustCompile(`(?mi)^\s*FROM\s+(?:--[^\s]+\s+)*([^\s]+)`) // Dockerfile grammar subset; image token only.
)

// Discovery contains only values found in allowlisted, project-root files or
// Git metadata explicitly associated with Root.
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
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return Discovery{}, fmt.Errorf("project path %s is not a git repository", root)
	}

	d := Discovery{Root: root, PackageManagers: make(map[string][]string), Services: make(map[string][]string)}
	if regular(root, "pyproject.toml") {
		if regular(root, "poetry.lock") {
			d.addManager(config.StackPython, "poetry")
		}
		if regular(root, "uv.lock") {
			d.addManager(config.StackPython, "uv")
		}
	}
	if regular(root, "requirements.in") {
		d.addManager(config.StackPython, "pip-tools")
	} else if regular(root, "requirements.txt") && len(d.PackageManagers[config.StackPython]) == 0 {
		d.addManager(config.StackPython, "requirements")
	}
	if regular(root, "package.json") {
		if regular(root, "package-lock.json") {
			d.addManager(config.StackNode, "npm")
		}
		if regular(root, "pnpm-lock.yaml") {
			d.addManager(config.StackNode, "pnpm")
		}
		if regular(root, "bun.lock") {
			d.addManager(config.StackNode, "bun")
		}
	}
	for _, name := range dockerNames {
		if regular(root, name) {
			d.DockerFiles = append(d.DockerFiles, name)
			images, err := dockerRuntimeImages(filepath.Join(root, name))
			if err != nil {
				return Discovery{}, err
			}
			d.RuntimeImages = append(d.RuntimeImages, images...)
		}
	}
	if len(d.DockerFiles) > 0 {
		d.Stacks = append(d.Stacks, config.StackDocker)
	}
	for _, name := range composeNames {
		if !regular(root, name) {
			continue
		}
		d.ComposeFiles = append(d.ComposeFiles, name)
		services, err := composeServices(filepath.Join(root, name))
		if err != nil {
			return Discovery{}, fmt.Errorf("read compose file %s: %w", name, err)
		}
		d.Services[name] = services
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

func dockerRuntimeImages(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Dockerfile: %w", err)
	}
	var images []string
	for _, match := range fromPattern.FindAllStringSubmatch(string(data), -1) {
		if strings.Contains(match[1], "@sha256:") {
			images = append(images, match[1])
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
					command := []string{manager, "run", factory}
					if factory == "test" && manager == "npm" {
						command = []string{"npm", "test"}
					}
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
			MinReleaseAgeDays: 7,
			SnapshotTTLHours:  24,
			Egress: config.EgressConfig{
				Network: "vuelta-update-egress", ProxyContainer: "vuelta-egress-proxy",
				ProxyURL: "http://vuelta-egress-proxy:3128",
			},
		},
		Autofix: config.AutofixConfig{
			Enabled: false, ClaudeBin: "claude", MaxTurns: 10, AllowedTools: "Read,Edit,Grep",
		},
		DeployTask: config.DeployTaskConfig{Mode: "git_tag", TagPrefix: "deploy-pending"},
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
		if err := toolchain.ValidateManagerSupport(stack, manager); err != nil {
			return config.Workspace{}, err
		}
	}
	verification, err := d.buildVerification(input, manager)
	if err != nil {
		return config.Workspace{}, err
	}
	branch, err := choose("--branch", input.Branch, d.Branches)
	if err != nil {
		return config.Workspace{}, err
	}
	remote, err := choose("--remote", input.Remote, d.Remotes)
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

func (d Discovery) buildVerification(input Input, manager string) (config.VerificationProfile, error) {
	if manager == "requirements" {
		if len(input.VerificationNames) != 0 {
			return config.VerificationProfile{}, errors.New("python/requirements has no safe mutation contract and cannot use --verification; register it as scan-only")
		}
		return config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly}, nil
	}
	if input.ScanOnly {
		if len(input.VerificationNames) != 0 {
			return config.VerificationProfile{}, errors.New("--scan-only cannot be combined with --verification")
		}
		return config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly}, nil
	}
	candidates := d.verificationCandidatesForManager(manager)
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

func (d Discovery) verificationCandidatesForManager(manager string) []config.VerificationStep {
	candidates := make([]config.VerificationStep, 0, len(d.VerificationCandidates))
	for _, candidate := range d.VerificationCandidates {
		if len(candidate.Command) > 0 && (candidate.Command[0] == "npm" || candidate.Command[0] == "pnpm" || candidate.Command[0] == "bun") && candidate.Command[0] != manager {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
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

func defaultAllowedPaths(stack, manager string, dockerFiles []string) []string {
	switch stack {
	case config.StackPython:
		switch manager {
		case "poetry":
			return []string{"pyproject.toml", "poetry.lock"}
		case "uv":
			return []string{"pyproject.toml", "uv.lock"}
		case "pip-tools":
			return []string{"requirements.in", "requirements.txt"}
		case "requirements":
			return []string{"requirements.txt"}
		}
	case config.StackNode:
		return []string{"package.json", map[string]string{"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "bun": "bun.lock"}[manager]}
	case config.StackDocker:
		return dockerFiles
	}
	return nil
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
