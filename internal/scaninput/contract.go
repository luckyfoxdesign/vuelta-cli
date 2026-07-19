// Package scaninput defines the exact repository files that each read-only
// scanner stage may receive. It never discovers files or accepts directories.
package scaninput

import (
	"fmt"
	"sort"

	"github.com/luckyfoxdesign/vuelta/internal/config"
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

var packageFiles = map[string][]File{
	"python/poetry": {
		{Path: "pyproject.toml", Category: CategoryManifest},
		{Path: "poetry.lock", Category: CategoryLock},
	},
	"python/uv": {
		{Path: "pyproject.toml", Category: CategoryManifest},
		{Path: "uv.lock", Category: CategoryLock},
	},
	"python/pip-tools": {
		{Path: "requirements.in", Category: CategoryManifest},
		{Path: "requirements.txt", Category: CategoryLock},
	},
	"node/npm": {
		{Path: "package.json", Category: CategoryManifest},
		{Path: "package-lock.json", Category: CategoryLock},
	},
	"node/pnpm": {
		{Path: "package.json", Category: CategoryManifest},
		{Path: "pnpm-lock.yaml", Category: CategoryLock},
	},
	"node/bun": {
		{Path: "package.json", Category: CategoryManifest},
		{Path: "bun.lock", Category: CategoryLock},
	},
}

var managerConfigs = map[string][]string{
	"npm":       {".npmrc"},
	"pnpm":      {".npmrc", "pnpm-workspace.yaml"},
	"bun":       {".npmrc", "bunfig.toml"},
	"poetry":    {"poetry.toml"},
	"uv":        {},
	"pip-tools": {"pip.conf"},
}

// PackageContract returns the manifest/lock inputs for candidate discovery.
// Manager configuration is optional and appears only after the explicit gate.
func PackageContract(ws config.Workspace, allowManagerConfig bool) (Contract, error) {
	files, ok := packageFiles[ws.Stack+"/"+ws.PackageManager]
	if !ok {
		if ws.Stack == config.StackDocker && ws.PackageManager == "" {
			return Contract{Stage: StagePackageCandidates}, nil
		}
		return Contract{}, fmt.Errorf("unsupported package input contract for stack=%q package_manager=%q", ws.Stack, ws.PackageManager)
	}
	contract := Contract{Stage: StagePackageCandidates, Files: append([]File(nil), files...)}
	if allowManagerConfig {
		for _, path := range managerConfigs[ws.PackageManager] {
			contract.Files = append(contract.Files, File{
				Path: path, Category: CategoryManagerConfig, Optional: true, ReviewedManagerConfig: true,
			})
		}
	}
	return contract, nil
}

// DependencyContract excludes manager configuration because CVE scanners need
// only recognized manifests and lockfiles.
func DependencyContract(ws config.Workspace) (Contract, error) {
	if ws.Stack == config.StackPython && ws.PackageManager == "" {
		return PythonRequirementsContract(), nil
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
	return Contract{Stage: StageDependencyCVE, Files: []File{{
		Path: "requirements.txt", Category: CategoryDependency,
	}}}
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
