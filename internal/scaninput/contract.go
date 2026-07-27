// Package scaninput defines the exact repository files that each read-only
// scanner stage may receive. It never discovers files or accepts directories.
package scaninput

import (
	"fmt"
	"sort"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
)

// Stage identifies one consumer of repository input.
type Stage string

const (
	StagePackageCandidates Stage = "package-candidates"
	StageDependencyCVE     Stage = "dependency-cve"
	StageDockerManifest    Stage = "docker-manifest"
	StagePolicy            Stage = "vulnerability-policy"
)

// Category is safe to report because it never contains a repository path.
type Category string

const (
	CategoryManifest       Category = "package-manifest"
	CategoryLock           Category = "package-lock"
	CategoryDependency     Category = "dependency-input"
	CategoryManagerConfig  Category = "package-manager-config"
	CategoryDockerManifest Category = "docker-manifest"
	CategoryPolicy         Category = "vulnerability-policy"
)

// File is one explicit repository-relative regular file.
type File struct {
	Path                  string
	Category              Category
	Optional              bool
	ReviewedManagerConfig bool
}

// Contract is a complete allowlist for one scan stage.
type Contract struct {
	Stage Stage
	Files []File
}

// PackageContract returns the manifest/lock inputs for candidate discovery.
// Manager configuration is optional and appears only after the explicit gate.
func PackageContract(ws config.Workspace, allowManagerConfig bool) (Contract, error) {
	if ws.Stack == config.StackDocker && ws.PackageManager == "" {
		return Contract{Stage: StagePackageCandidates}, nil
	}
	adapter, err := adapterFor(ws.Stack, ws.PackageManager)
	if err != nil {
		return Contract{}, fmt.Errorf("unsupported package input contract for stack=%q package_manager=%q: %w", ws.Stack, ws.PackageManager, err)
	}
	provider, ok := adapter.(ecosystem.InputProvider)
	if !ok {
		return Contract{}, &ecosystem.CapabilityError{Key: adapter.Key(), Capability: "scan-input"}
	}
	if resolver, ok := adapter.(ecosystem.RootInputProvider); ok {
		contract, resolveErr := resolver.PackageInputForRoot(ws.Path, allowManagerConfig)
		if resolveErr != nil {
			return Contract{}, resolveErr
		}
		return fromEcosystemContract(contract), nil
	}
	return fromEcosystemContract(provider.PackageInput(allowManagerConfig)), nil
}

// DependencyContract excludes manager configuration because CVE scanners need
// only recognized manifests and lockfiles.
func DependencyContract(ws config.Workspace) (Contract, error) {
	if ws.Stack == config.StackPython && ws.PackageManager == "" {
		return PythonRequirementsContract(), nil
	}
	adapter, err := adapterFor(ws.Stack, ws.PackageManager)
	if err == nil {
		if resolver, ok := adapter.(ecosystem.RootInputProvider); ok {
			contract, resolveErr := resolver.DependencyInputForRoot(ws.Path)
			if resolveErr != nil {
				return Contract{}, resolveErr
			}
			return fromEcosystemContract(contract), nil
		}
	}
	contract, err := PackageContract(ws, false)
	if err != nil {
		return Contract{}, err
	}
	contract.Stage = StageDependencyCVE
	return contract, nil
}

// PythonRequirementsContract returns the manager-independent dependency
// input accepted by CVE scanners. A requirements.txt file alone does not
// imply that pip-tools owns it and never enables package updates.
func PythonRequirementsContract() Contract {
	adapter, err := adapterFor(config.StackPython, "requirements")
	if err != nil {
		return Contract{Stage: StageDependencyCVE}
	}
	provider, ok := adapter.(ecosystem.InputProvider)
	if !ok {
		return Contract{Stage: StageDependencyCVE}
	}
	return fromEcosystemContract(provider.DependencyInput())
}

func adapterFor(stack, packageManager string) (ecosystem.Adapter, error) {
	registry, err := catalog.New()
	if err != nil {
		return nil, err
	}
	return registry.Lookup(stack, packageManager)
}

func fromEcosystemContract(source ecosystem.InputContract) Contract {
	contract := Contract{Stage: Stage(source.Stage), Files: make([]File, len(source.Files))}
	for index, file := range source.Files {
		contract.Files[index] = File{
			Path: file.Path, Category: Category(file.Category), Optional: file.Optional,
			ReviewedManagerConfig: file.ReviewedManagerConfig,
		}
	}
	return contract
}

// DockerContract returns only explicitly configured Docker manifest files.
func DockerContract(ws config.Workspace) Contract {
	contract := Contract{Stage: StageDockerManifest}
	if ws.DockerImages == nil {
		return contract
	}
	for _, path := range ws.DockerImages.Files {
		contract.Files = append(contract.Files, File{Path: path, Category: CategoryDockerManifest})
	}
	return contract
}

// PolicyContract returns the one configured vulnerability policy.
func PolicyContract(path string) Contract {
	contract := Contract{Stage: StagePolicy}
	if path != "" {
		contract.Files = []File{{Path: path, Category: CategoryPolicy}}
	}
	return contract
}

// ManifestCategories returns only categories for files that were actually
// validated and included; absent optional inputs are not reported.
func ManifestCategories(manifest Manifest) []string {
	seen := make(map[string]bool)
	for _, entry := range manifest.Entries {
		seen[string(entry.Category)] = true
	}
	categories := make([]string, 0, len(seen))
	for category := range seen {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories
}

// ParseStages validates persisted stage names and returns canonical ordering.
func ParseStages(values []string) ([]Stage, error) {
	allowed := map[Stage]bool{
		StagePackageCandidates: true,
		StageDependencyCVE:     true,
		StageDockerManifest:    true,
		StagePolicy:            true,
	}
	seen := make(map[Stage]bool, len(values))
	stages := make([]Stage, 0, len(values))
	for _, value := range values {
		stage := Stage(value)
		if !allowed[stage] || seen[stage] {
			return nil, fmt.Errorf("invalid or duplicate scan input stage %q", value)
		}
		seen[stage] = true
		stages = append(stages, stage)
	}
	sort.Slice(stages, func(i, j int) bool { return stages[i] < stages[j] })
	return stages, nil
}
