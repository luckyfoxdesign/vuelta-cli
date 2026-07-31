// Package deploy discovers and executes machine-owned deployments without
// writing configuration into managed repositories.
package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"gopkg.in/yaml.v3"
)

const ContractVersion = 1

var (
	serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	commitPattern      = regexp.MustCompile(`^[a-f0-9]{40}$`)
	healthURLPattern   = regexp.MustCompile(`(?i)(?:https?://)?(?:localhost|127\.0\.0\.1):([0-9]{2,5})(/[A-Za-z0-9_./~-]*)?`)
)

var composeGroups = [][]string{
	{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"},
	{"compose.prod.yaml", "compose.prod.yml", "docker-compose.prod.yaml", "docker-compose.prod.yml"},
}

var migrationCandidates = []string{
	"migrations",
	"alembic/versions",
	"db/migrations",
	"prisma/migrations",
}

// Contract is a derived, machine-owned deployment description. It contains
// structural metadata only: never environment values or project file content.
type Contract struct {
	Version          int       `json:"version"`
	Project          string    `json:"project"`
	Root             string    `json:"-"`
	Repository       string    `json:"repository"`
	Branch           string    `json:"branch"`
	Commit           string    `json:"commit"`
	ComposeFiles     []string  `json:"compose_files"`
	Services         []Service `json:"services"`
	ExternalNetworks []string  `json:"external_networks"`
	TrafficService   string    `json:"traffic_service"`
	StableUpstream   string    `json:"stable_upstream"`
	InternalPort     int       `json:"internal_port"`
	HealthPath       string    `json:"health_path"`
	MigrationPaths   []string  `json:"migration_paths"`
	Fingerprint      string    `json:"fingerprint"`
	Blockers         []string  `json:"blockers"`
	RepositoryWrites bool      `json:"repository_writes"`
}

// Service is the safe subset of one merged Compose service needed to create
// an exact-image slot outside the repository.
type Service struct {
	Name            string   `json:"name"`
	ContainerName   string   `json:"container_name,omitempty"`
	Role            string   `json:"role"`
	BuildContext    string   `json:"build_context"`
	Dockerfile      string   `json:"dockerfile"`
	BuildTarget     string   `json:"build_target,omitempty"`
	Networks        []string `json:"networks"`
	HasHealthcheck  bool     `json:"has_healthcheck"`
	InternalPort    int      `json:"internal_port,omitempty"`
	HealthPath      string   `json:"health_path,omitempty"`
	PersistentState bool     `json:"persistent_state"`
	ExternalNetwork bool     `json:"external_network"`
}

type composeDocument struct {
	Services map[string]composeService `yaml:"services"`
	Networks map[string]composeNetwork `yaml:"networks"`
}

type composeNetwork struct {
	Name     string    `yaml:"name"`
	External yaml.Node `yaml:"external"`
}

type composeService struct {
	Image         string    `yaml:"image"`
	Build         yaml.Node `yaml:"build"`
	Profiles      yaml.Node `yaml:"profiles"`
	ContainerName string    `yaml:"container_name"`
	Command       yaml.Node `yaml:"command"`
	EnvFile       yaml.Node `yaml:"env_file"`
	Networks      yaml.Node `yaml:"networks"`
	Volumes       yaml.Node `yaml:"volumes"`
	Healthcheck   yaml.Node `yaml:"healthcheck"`
	Ports         yaml.Node `yaml:"ports"`
	Expose        yaml.Node `yaml:"expose"`
	Labels        yaml.Node `yaml:"labels"`
}

// Discover derives a deployment contract from one exact configured workspace.
// It reads only fixed root-level Compose files, standard migration directory
// names, and reviewed Git metadata. It never writes inside root.
func Discover(ctx context.Context, workspace config.Workspace) (Contract, error) {
	root, err := canonicalRoot(workspace.Path)
	if err != nil {
		return Contract{}, err
	}
	contract := Contract{
		Version: ContractVersion, Project: config.WorkspaceName(workspace), Root: root,
		Branch: workspace.Branch, RepositoryWrites: false,
	}
	contract.Repository, err = githubRepository(ctx, root, workspace.Remote)
	if err != nil {
		contract.Blockers = append(contract.Blockers, "github_repository_unresolved")
	}
	contract.Commit, err = gitCommit(ctx, root)
	if err != nil {
		contract.Blockers = append(contract.Blockers, "git_commit_unresolved")
	}

	contract.ComposeFiles, err = selectComposeFiles(root)
	if err != nil {
		contract.Blockers = append(contract.Blockers, err.Error())
	}
	merged := make(map[string]composeService)
	networks := make(map[string]composeNetwork)
	for _, relative := range contract.ComposeFiles {
		document, readErr := readCompose(filepath.Join(root, relative))
		if readErr != nil {
			contract.Blockers = append(contract.Blockers, "compose_invalid:"+relative)
			continue
		}
		for name, service := range document.Services {
			if !serviceNamePattern.MatchString(name) {
				contract.Blockers = append(contract.Blockers, "compose_service_name_invalid")
				continue
			}
			merged[name] = mergeService(merged[name], service)
		}
		for name, network := range document.Networks {
			networks[name] = network
		}
	}
	for name, network := range networks {
		if externalNetwork(network) {
			networkName := network.Name
			if networkName == "" {
				networkName = name
			}
			if serviceNamePattern.MatchString(networkName) {
				contract.ExternalNetworks = append(contract.ExternalNetworks, networkName)
			} else {
				contract.Blockers = append(contract.Blockers, "external_network_name_invalid")
			}
		}
	}
	sort.Strings(contract.ExternalNetworks)

	for name, service := range merged {
		if nonReleaseService(name, service) {
			continue
		}
		build, ok, buildErr := buildSpec(service.Build)
		if buildErr != nil {
			contract.Blockers = append(contract.Blockers, "build_contract_invalid:"+name)
			continue
		}
		if !ok {
			continue
		}
		port, healthPath := serviceHealth(service)
		role := "singleton"
		if hasHealthcheck(service.Healthcheck) && port > 0 {
			role = "web"
		}
		serviceNetworks := nodeKeys(service.Networks)
		usesExternal := false
		for _, networkName := range serviceNetworks {
			if network, ok := networks[networkName]; ok && externalNetwork(network) {
				usesExternal = true
			}
		}
		contract.Services = append(contract.Services, Service{
			Name: name, ContainerName: boundedName(service.ContainerName), Role: role,
			BuildContext: build.Context, Dockerfile: build.Dockerfile, BuildTarget: build.Target,
			Networks: serviceNetworks, HasHealthcheck: hasHealthcheck(service.Healthcheck),
			InternalPort: port, HealthPath: healthPath,
			PersistentState: nodeLength(service.Volumes) > 0, ExternalNetwork: usesExternal,
		})
	}
	sort.Slice(contract.Services, func(i, j int) bool { return contract.Services[i].Name < contract.Services[j].Name })
	builds := make(map[string]bool)
	for _, service := range contract.Services {
		key := service.BuildContext + "\x00" + service.Dockerfile + "\x00" + service.BuildTarget
		builds[key] = true
	}
	if len(builds) > 1 {
		contract.Blockers = append(contract.Blockers, "release_services_use_different_builds")
	}

	var web []Service
	for _, service := range contract.Services {
		if service.Role == "web" {
			web = append(web, service)
		}
	}
	switch len(web) {
	case 0:
		contract.Blockers = append(contract.Blockers, "healthy_web_service_not_detected")
	case 1:
		contract.TrafficService = web[0].Name
		contract.StableUpstream = web[0].ContainerName
		if contract.StableUpstream == "" {
			contract.StableUpstream = web[0].Name
		}
		contract.InternalPort = web[0].InternalPort
		contract.HealthPath = web[0].HealthPath
	default:
		contract.Blockers = append(contract.Blockers, "multiple_healthy_web_services")
	}
	if len(contract.Services) == 0 {
		contract.Blockers = append(contract.Blockers, "local_release_services_not_detected")
	}
	for _, service := range contract.Services {
		if service.Role != "web" && service.ExternalNetwork {
			contract.Blockers = append(contract.Blockers, "external_service_without_healthcheck:"+service.Name)
		}
	}

	for _, relative := range migrationCandidates {
		info, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
		if statErr == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			contract.MigrationPaths = append(contract.MigrationPaths, relative)
		}
	}
	sort.Strings(contract.MigrationPaths)
	contract.Blockers = uniqueSorted(contract.Blockers)
	contract.Fingerprint, err = fingerprint(contract)
	if err != nil {
		return Contract{}, err
	}
	return contract, nil
}

type buildContract struct {
	Context    string
	Dockerfile string
	Target     string
}

func buildSpec(node yaml.Node) (buildContract, bool, error) {
	if node.Kind == 0 || node.Tag == "!!null" {
		return buildContract{}, false, nil
	}
	build := buildContract{Context: ".", Dockerfile: "Dockerfile"}
	switch node.Kind {
	case yaml.ScalarNode:
		build.Context = node.Value
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index].Value, node.Content[index+1]
			if value.Kind != yaml.ScalarNode {
				continue
			}
			switch key {
			case "context":
				build.Context = value.Value
			case "dockerfile":
				build.Dockerfile = value.Value
			case "target":
				build.Target = value.Value
			}
		}
	default:
		return buildContract{}, false, errors.New("build must be a scalar or mapping")
	}
	for label, value := range map[string]string{"context": build.Context, "dockerfile": build.Dockerfile} {
		if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == ".." ||
			strings.HasPrefix(value, ".."+string(filepath.Separator)) || strings.ContainsRune(value, '\x00') {
			return buildContract{}, false, fmt.Errorf("build %s is not a safe project-relative path", label)
		}
	}
	if build.Target != "" && !serviceNamePattern.MatchString(build.Target) {
		return buildContract{}, false, errors.New("build target is invalid")
	}
	return build, true, nil
}

func canonicalRoot(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve deployment root: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve deployment root: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", errors.New("deployment root must be an existing directory")
	}
	return canonical, nil
}

func selectComposeFiles(root string) ([]string, error) {
	var selected []string
	for groupIndex, group := range composeGroups {
		var matches []string
		for _, name := range group {
			info, err := os.Lstat(filepath.Join(root, name))
			if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
				matches = append(matches, name)
			}
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf("compose_group_%d_ambiguous", groupIndex)
		}
		selected = append(selected, matches...)
	}
	if len(selected) == 0 {
		return nil, errors.New("production_compose_not_detected")
	}
	return selected, nil
}

func readCompose(path string) (composeDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return composeDocument{}, err
	}
	var document composeDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		return composeDocument{}, err
	}
	if len(document.Services) == 0 {
		return composeDocument{}, errors.New("compose services are required")
	}
	return document, nil
}

func externalNetwork(network composeNetwork) bool {
	if network.External.Kind == yaml.ScalarNode {
		return strings.EqualFold(network.External.Value, "true")
	}
	if network.External.Kind == yaml.MappingNode {
		return true
	}
	return network.Name != ""
}

func mergeService(base, override composeService) composeService {
	if override.Image != "" {
		base.Image = override.Image
	}
	if override.ContainerName != "" {
		base.ContainerName = override.ContainerName
	}
	for destination, source := range map[*yaml.Node]yaml.Node{
		&base.Build: override.Build, &base.Command: override.Command, &base.EnvFile: override.EnvFile,
		&base.Profiles: override.Profiles,
		&base.Networks: override.Networks, &base.Volumes: override.Volumes,
		&base.Healthcheck: override.Healthcheck, &base.Ports: override.Ports,
		&base.Expose: override.Expose, &base.Labels: override.Labels,
	} {
		if source.Kind != 0 {
			*destination = source
		}
	}
	return base
}

func nonReleaseService(name string, service composeService) bool {
	switch strings.ToLower(name) {
	case "test", "tests", "lint", "format", "typecheck", "build", "dev":
		return true
	}
	return nodeLength(service.Profiles) > 0
}

func hasHealthcheck(node yaml.Node) bool {
	if node.Kind != yaml.MappingNode {
		return false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == "disable" && strings.EqualFold(node.Content[index+1].Value, "true") {
			return false
		}
		if node.Content[index].Value == "test" {
			return node.Content[index+1].Kind != 0
		}
	}
	return false
}

func serviceHealth(service composeService) (int, string) {
	for _, node := range []yaml.Node{service.Healthcheck, service.Expose, service.Ports} {
		serialized, err := yaml.Marshal(node)
		if err != nil {
			continue
		}
		if match := healthURLPattern.FindSubmatch(serialized); len(match) >= 2 {
			port, _ := strconv.Atoi(string(match[1]))
			if port > 0 && port <= 65535 {
				path := "/"
				if len(match) > 2 && len(match[2]) > 0 {
					path = string(match[2])
				}
				return port, path
			}
		}
	}
	return 0, ""
}

func nodeKeys(node yaml.Node) []string {
	var values []string
	switch node.Kind {
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode && serviceNamePattern.MatchString(item.Value) {
				values = append(values, item.Value)
			}
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			if serviceNamePattern.MatchString(node.Content[index].Value) {
				values = append(values, node.Content[index].Value)
			}
		}
	}
	return uniqueSorted(values)
}

func nodeLength(node yaml.Node) int {
	switch node.Kind {
	case yaml.SequenceNode:
		return len(node.Content)
	case yaml.MappingNode:
		return len(node.Content) / 2
	default:
		return 0
	}
}

func githubRepository(ctx context.Context, root, remote string) (string, error) {
	if remote == "" {
		remote = "origin"
	}
	if !serviceNamePattern.MatchString(remote) {
		return "", errors.New("git remote name is invalid")
	}
	output, err := gitexec.Output(ctx, root, "remote", "get-url", remote)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(string(output))
	var repository string
	switch {
	case strings.HasPrefix(raw, "git@github.com:"):
		repository = strings.TrimPrefix(raw, "git@github.com:")
	default:
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Hostname() != "github.com" || parsed.User != nil {
			return "", errors.New("git remote is not an approved GitHub URL")
		}
		repository = strings.TrimPrefix(parsed.Path, "/")
	}
	repository = strings.TrimSuffix(repository, ".git")
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(repository) ||
		strings.Contains(repository, "..") {
		return "", errors.New("GitHub repository identity is invalid")
	}
	return repository, nil
}

func gitCommit(ctx context.Context, root string) (string, error) {
	output, err := gitexec.Output(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(output))
	if !commitPattern.MatchString(commit) {
		return "", errors.New("git HEAD is not a full lowercase commit")
	}
	return commit, nil
}

func fingerprint(contract Contract) (string, error) {
	copyContract := contract
	copyContract.Root = ""
	copyContract.Fingerprint = ""
	data, err := json.Marshal(copyContract)
	if err != nil {
		return "", fmt.Errorf("encode deployment contract: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func boundedName(value string) string {
	if serviceNamePattern.MatchString(value) && len(value) <= 128 {
		return value
	}
	return ""
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
