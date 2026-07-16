package configinit

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/gitpath"
	"gopkg.in/yaml.v3"
)

var (
	composeNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
	dockerNames  = []string{"Dockerfile", "dockerfile"}
	fromPattern  = regexp.MustCompile(`(?mi)^\s*FROM\s+(?:--[^\s]+\s+)*([^\s]+)`) // Dockerfile grammar subset; image token only.
)

// Discovery contains only values found in allowlisted, project-root files or
// Git metadata explicitly associated with Root.
type Discovery struct {
	Root            string
	Stacks          []string
	PackageManagers map[string][]string
	ComposeFiles    []string
	Services        map[string][]string
	Branches        []string
	Remotes         []string
	DockerFiles     []string
	RuntimeImages   []string
}

// Input supplies choices that could not be made deterministically. Repeated
// fields correspond to repeatable CLI flags.
type Input struct {
	Name, Stack, PackageManager, ComposeFile, TestService, Branch, Remote string
	AllowedPaths, DockerFiles, RuntimeImages                              []string
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

func gitValues(root string, args ...string) []string {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return uniqueSorted(strings.Fields(string(out)))
}

// NewConfig returns the empty, validated container created by config init.
// It deliberately contains no workspace and no credentials.
func NewConfig() *config.Config {
	return &config.Config{
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
			Images: defaultImages(),
			Tools:  map[string]string{"npm_check_updates": "17.1.16", "poetry": "2.1.1", "pip_tools": "7.5.0"},
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
	}
	composeFile, err := choose("--compose-file", input.ComposeFile, d.ComposeFiles)
	if err != nil {
		return config.Workspace{}, err
	}
	if !contains(d.ComposeFiles, composeFile) {
		return config.Workspace{}, fmt.Errorf("--compose-file %q is not a detected project-root Compose file", composeFile)
	}
	service, err := choose("--test-service", input.TestService, d.Services[composeFile])
	if err != nil {
		return config.Workspace{}, err
	}
	if !contains(d.Services[composeFile], service) {
		return config.Workspace{}, fmt.Errorf("--test-service %q is not a service in %s", service, composeFile)
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
		AllowedChangedPaths: uniqueSorted(allowed),
		Test:                config.TestProfile{ComposeFile: composeFile, Service: service, RunArgs: []string{"--rm"}}}
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
	return ws, nil
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
