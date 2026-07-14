// Package configinit deterministically detects a selected project's supported
// files and generates a validated Vuelta configuration. It never walks parent
// directories or reads unallowlisted files.
package configinit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"gopkg.in/yaml.v3"
)

const trivyImage = "aquasec/trivy@sha256:1c60229e5bc7f5830bf8aeb829442cb01f71ce3cd5b4d1b754f1f166c9945951"

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
	Stack, PackageManager, ComposeFile, TestService, Branch, Remote string
	AllowedPaths, DockerFiles, RuntimeImages                        []string
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

// Build returns a config only when every required selection is explicit or
// uniquely detected. It validates the generated config before it is written.
func (d Discovery) Build(input Input) (*config.Config, error) {
	stack, err := choose("--stack", input.Stack, d.Stacks)
	if err != nil {
		return nil, err
	}
	if !contains(d.Stacks, stack) {
		return nil, fmt.Errorf("--stack %q was not detected in the selected project", stack)
	}
	manager := ""
	if stack != config.StackDocker {
		manager, err = choose("--package-manager", input.PackageManager, d.PackageManagers[stack])
		if err != nil {
			return nil, err
		}
		if !contains(d.PackageManagers[stack], manager) {
			return nil, fmt.Errorf("--package-manager %q was not detected for stack %q", manager, stack)
		}
	}
	composeFile, err := choose("--compose-file", input.ComposeFile, d.ComposeFiles)
	if err != nil {
		return nil, err
	}
	if !contains(d.ComposeFiles, composeFile) {
		return nil, fmt.Errorf("--compose-file %q is not a detected project-root Compose file", composeFile)
	}
	service, err := choose("--test-service", input.TestService, d.Services[composeFile])
	if err != nil {
		return nil, err
	}
	if !contains(d.Services[composeFile], service) {
		return nil, fmt.Errorf("--test-service %q is not a service in %s", service, composeFile)
	}
	branch, err := choose("--branch", input.Branch, d.Branches)
	if err != nil {
		return nil, err
	}
	remote, err := choose("--remote", input.Remote, d.Remotes)
	if err != nil {
		return nil, err
	}

	allowed := input.AllowedPaths
	if len(allowed) == 0 {
		allowed = defaultAllowedPaths(stack, manager, d.DockerFiles)
	}
	if len(allowed) == 0 {
		return nil, &MissingValueError{Flag: "--allow-path"}
	}
	for _, path := range allowed {
		if !safeProjectPath(path) {
			return nil, fmt.Errorf("--allow-path %q escapes the selected project", path)
		}
	}
	ws := config.Workspace{Path: d.Root, Stack: stack, PackageManager: manager, Branch: branch, Remote: remote,
		Test: config.TestProfile{ComposeFile: composeFile, Service: service, RunArgs: []string{"--rm"}}}
	if stack == config.StackDocker {
		files := input.DockerFiles
		if len(files) == 0 {
			files = d.DockerFiles
		}
		for _, file := range files {
			if !contains(d.DockerFiles, file) {
				return nil, fmt.Errorf("--docker-file %q is not a detected project-root Dockerfile", file)
			}
		}
		images := input.RuntimeImages
		if len(images) == 0 {
			images = d.RuntimeImages
		}
		ws.DockerImages = &config.DockerImagesSpec{Files: uniqueSorted(files), RuntimeImages: uniqueSorted(images), Platforms: []string{"linux/amd64"}}
	}
	cfg := &config.Config{
		VulnScan:   config.VulnScanConfig{DependencySource: "trivy", Image: trivyImage, FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24},
		Update:     config.UpdateConfig{MinReleaseAgeDays: 7, Egress: config.EgressConfig{Network: "vuelta-update-egress", ProxyContainer: "vuelta-egress-proxy", ProxyURL: "http://vuelta-egress-proxy:3128"}, Images: defaultImages(), Tools: map[string]string{"npm_check_updates": "17.1.16", "poetry": "2.1.1", "pip_tools": "7.5.0"}},
		Autofix:    config.AutofixConfig{Enabled: false, ClaudeBin: "claude", MaxTurns: 10, AllowedTools: "Read,Edit,Grep"},
		DeployTask: config.DeployTaskConfig{Mode: "git_tag", TagPrefix: "deploy-pending"}, Workspaces: []config.Workspace{ws},
		Git: config.GitConfig{PushMode: "review_branch", AllowedChangedPaths: uniqueSorted(allowed)},
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generated configuration is invalid: %w", err)
	}
	return cfg, nil
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

func defaultImages() map[string]string {
	return map[string]string{
		"python-poetry":    "python:3.12-slim@sha256:b3acc63118e4dde71287074936a02afe84748dc6a7ef9ed544fea2745cfa6153",
		"python-uv":        "ghcr.io/astral-sh/uv:0.6.14@sha256:a06fb406bda92ac2c105cd45111a206b80294215d6480fa4ce4fd931ab66d7b2",
		"python-pip-tools": "python:3.12-slim@sha256:b3acc63118e4dde71287074936a02afe84748dc6a7ef9ed544fea2745cfa6153",
		"node":             "node:22@sha256:e59e7e103c548864aa008d397b8487c96c539538ca8ec724330fd5cb35d609b3",
		"bun":              "oven/bun:1.2@sha256:24b8162f18519860276bddcd5cf74045815be0bd1023b35061fb926f1b7989d2",
	}
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

func safeProjectPath(path string) bool {
	if path == "" || filepath.IsAbs(path) {
		return false
	}
	cleaned := filepath.Clean(path)
	return cleaned != ".." && !strings.HasPrefix(cleaned, ".."+string(filepath.Separator))
}

// Write serializes an already-validated config. It never overwrites an
// existing config unless force is true and refuses symlink destinations.
func Write(cfg *config.Config, path string, force bool) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate generated config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to write config through a symlink")
		}
		if !force {
			return fmt.Errorf("config %s already exists (use --force to overwrite)", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect config path: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serialize config: %w", err)
	}
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("write config: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close config: %w", closeErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict config permissions: %w", err)
	}
	return nil
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
