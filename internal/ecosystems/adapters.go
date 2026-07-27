// Package ecosystems contains Vuelta's concrete built-in ecosystem adapters.
// Registration is performed explicitly by internal/ecosystems/catalog.
package ecosystems

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"gopkg.in/yaml.v3"
)

const (
	adapterVersion         = "1"
	defaultNCUVersion      = "22.2.9"
	defaultPoetryVersion   = "2.4.1"
	defaultUVVersion       = "0.11.29"
	defaultPipVersion      = "25.0.1"
	defaultPipToolsVersion = "7.5.0"
	defaultPipScanner      = "1.2.0"
)

type baseAdapter struct {
	key      ecosystem.Key
	metadata ecosystem.Metadata
}

func (a baseAdapter) Key() ecosystem.Key           { return a.key }
func (a baseAdapter) Metadata() ecosystem.Metadata { return a.metadata }

type inputCapability struct {
	files          []ecosystem.InputFile
	managerConfigs []string
}

func (c inputCapability) PackageInput(allowManagerConfig bool) ecosystem.InputContract {
	files := append([]ecosystem.InputFile(nil), c.files...)
	if allowManagerConfig {
		for _, path := range c.managerConfigs {
			files = append(files, ecosystem.InputFile{
				Path: path, Category: ecosystem.InputCategoryManagerConfig,
				Optional: true, ReviewedManagerConfig: true,
			})
		}
	}
	return ecosystem.InputContract{Stage: ecosystem.InputStagePackageCandidates, Files: files}
}

func (c inputCapability) DependencyInput() ecosystem.InputContract {
	return ecosystem.InputContract{
		Stage: ecosystem.InputStageDependencyCVE,
		Files: append([]ecosystem.InputFile(nil), c.files...),
	}
}

type detectionCapability struct {
	required []string
}

func (c detectionCapability) Detect(root string) (bool, error) {
	for _, path := range c.required {
		if !ecosystem.IsRegularRootFile(root, path) {
			return false, nil
		}
	}
	return true, nil
}

type verificationCapability struct {
	manager string
}

func (c verificationCapability) VerificationCommand(script string) []string {
	if c.manager == "npm" && script == "test" {
		return []string{"npm", "test"}
	}
	return []string{c.manager, "run", script}
}

func (c verificationCapability) VerificationScript(command []string) (string, bool) {
	if c.manager == "" || len(command) == 0 || command[0] != c.manager {
		return "", false
	}
	if c.manager == "npm" && len(command) >= 2 && command[1] == "test" {
		return "test", true
	}
	if len(command) >= 3 && command[1] == "run" {
		return command[2], true
	}
	return "", false
}

type constraintCapability struct {
	key    ecosystem.Key
	detect func(string, ecosystem.Key, string) (ecosystem.Constraints, error)
}

func (c constraintCapability) DetectConstraints(root, platform string) (ecosystem.Constraints, error) {
	return c.detect(root, c.key, platform)
}

type toolchainCapability struct {
	resolve func(ecosystem.Constraints) (ecosystem.ToolchainSpec, error)
}

func (c toolchainCapability) DefaultToolchain(constraints ecosystem.Constraints) (ecosystem.ToolchainSpec, error) {
	return c.resolve(constraints)
}

type scannerCapability struct {
	expectedScanner string
	resolve         func(ecosystem.ScannerRequest) (ecosystem.ScannerSpec, error)
}

type profilePolicyCapability struct {
	expectedScanner string
	lockFormats     []string
	versionStyle    string
}

func (c profilePolicyCapability) ProfilePolicy() ecosystem.ProfilePolicy {
	return ecosystem.ProfilePolicy{
		ExpectedScanner:    c.expectedScanner,
		AllowedLockFormats: append([]string(nil), c.lockFormats...),
		VersionOutputStyle: c.versionStyle,
	}
}

func (c scannerCapability) Scanner(request ecosystem.ScannerRequest) (ecosystem.ScannerSpec, error) {
	if request.ProfileScanner != "" && request.ProfileScanner != c.expectedScanner {
		return ecosystem.ScannerSpec{}, fmt.Errorf("scanner %q is incompatible with expected %q", request.ProfileScanner, c.expectedScanner)
	}
	return c.resolve(request)
}

type mutationCapability struct {
	resolve func(ecosystem.MutationRequest) (ecosystem.MutationSpec, error)
}

type plannedMutationCapability struct {
	resolve func(ecosystem.PlannedMutationRequest) (ecosystem.PlannedMutationSpec, error)
}

func (c plannedMutationCapability) PlannedMutation(request ecosystem.PlannedMutationRequest) (ecosystem.PlannedMutationSpec, error) {
	return c.resolve(request)
}

func (c mutationCapability) Mutation(request ecosystem.MutationRequest) (ecosystem.MutationSpec, error) {
	return c.resolve(request)
}

type changeCapability struct {
	paths []string
}

func (c changeCapability) AllowedChangedPaths() []string {
	return append([]string(nil), c.paths...)
}

type scanningAdapter struct {
	baseAdapter
	inputCapability
	detectionCapability
	verificationCapability
	constraintCapability
	toolchainCapability
	profilePolicyCapability
	scannerCapability
	decoderCapability
	changeCapability
}

type mutableAdapter struct {
	scanningAdapter
	mutationCapability
	plannedMutationCapability
}

type npmAdapter struct {
	mutableAdapter
}

type pipToolsAdapter struct {
	mutableAdapter
}

type unsupportedAdapter struct {
	baseAdapter
	inputCapability
	detectionCapability
	verificationCapability
	constraintCapability
	profilePolicyCapability
	changeCapability
}

// NPM returns the node/npm built-in adapter.
func NPM() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "node", PackageManager: "npm"}
	scanner := scannerCapability{expectedScanner: "ncu", resolve: func(request ecosystem.ScannerRequest) (ecosystem.ScannerSpec, error) {
		args := []string{"ncu", "--jsonUpgraded", "--removeRange"}
		if !request.InstalledTool {
			args = []string{"npx", "npm-check-updates@" + request.ScannerVersion, "--jsonUpgraded", "--removeRange"}
		}
		if !request.InstalledTool || request.MinReleaseAgeDays > 0 {
			args = append(args, "--cooldown", strconv.Itoa(request.MinReleaseAgeDays*24))
		}
		return ecosystem.ScannerSpec{
			Kind: "npm", ExpectedScanner: "ncu", Args: args, Decoder: "ncu",
			ReleaseAge: true, LegacyImageKey: "node", LegacyToolKey: "npm_check_updates",
		}, nil
	}}
	return npmAdapter{mutableAdapter: mutableAdapter{
		scanningAdapter: scanningAdapter{
			baseAdapter:            base(key, "npm", 100, false, ""),
			inputCapability:        inputs("package.json", "package-lock.json", []string{".npmrc"}),
			verificationCapability: verificationCapability{manager: "npm"},
			constraintCapability: constraintCapability{
				key: key, detect: detectNodeConstraints,
			},
			toolchainCapability: nodeToolchain(key, "ncu", defaultNCUVersion, []string{"npm-v2", "npm-v3"}, true),
			profilePolicyCapability: profilePolicyCapability{
				expectedScanner: "ncu", lockFormats: []string{"npm-v2", "npm-v3"}, versionStyle: "exact",
			},
			scannerCapability: scanner,
			decoderCapability: decoderCapability{kind: "npm"},
			changeCapability:  changes("package.json", "package-lock.json", "npm-shrinkwrap.json"),
		},
		mutationCapability: mutationCapability{resolve: func(request ecosystem.MutationRequest) (ecosystem.MutationSpec, error) {
			if request.ProfileScanner != "ncu" {
				return ecosystem.MutationSpec{}, fmt.Errorf("npm mutation requires ncu scanner, got %q", request.ProfileScanner)
			}
			lockFile, err := npmMutationLock(request.Root)
			if err != nil {
				return ecosystem.MutationSpec{}, err
			}
			first := []string{"ncu", "-u"}
			if !request.InstalledTool {
				first = []string{"npx", "npm-check-updates@" + request.ScannerVersion, "-u"}
			}
			return ecosystem.MutationSpec{
				LockFile:       lockFile,
				Commands:       [][]string{first, {"npm", "install"}},
				LegacyImageKey: "node", LegacyToolKey: "npm_check_updates",
			}, nil
		}},
		plannedMutationCapability: plannedMutationCapability{resolve: func(request ecosystem.PlannedMutationRequest) (ecosystem.PlannedMutationSpec, error) {
			if request.ProfileScanner != "ncu" {
				return ecosystem.PlannedMutationSpec{}, fmt.Errorf("npm planned mutation requires ncu scanner, got %q", request.ProfileScanner)
			}
			lockFile, err := npmMutationLock(request.Root)
			if err != nil {
				return ecosystem.PlannedMutationSpec{}, err
			}
			mutations := make([]ecosystem.CandidateMutation, 0, len(request.Candidates))
			for _, candidate := range request.Candidates {
				args := []string{"ncu"}
				if !request.InstalledTool {
					args = []string{"npx", "npm-check-updates@" + request.ScannerVersion}
				}
				args = append(args, "--filter", candidate.Name)
				if request.MinReleaseAgeDays > 0 {
					args = append(args, "--cooldown", strconv.Itoa(request.MinReleaseAgeDays*24))
				}
				args = append(args, "-u")
				mutations = append(mutations, ecosystem.CandidateMutation{Candidate: candidate, Commands: [][]string{args}})
			}
			final := []string{"npm", "install", "--no-audit", "--no-fund"}
			if !request.AllowScripts {
				final = append(final, "--ignore-scripts")
			}
			return ecosystem.PlannedMutationSpec{
				LockFile: lockFile, LegacyImageKey: "node", LegacyToolKey: "npm_check_updates",
				Mutations: mutations, FinalCommands: [][]string{final}, Validation: "npm-exact-targets",
			}, nil
		}},
	}}
}

// PNPM returns the node/pnpm built-in adapter.
func PNPM() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "node", PackageManager: "pnpm"}
	return mutableAdapter{
		scanningAdapter: scanningAdapter{
			baseAdapter:            base(key, "pnpm", 100, false, ""),
			inputCapability:        inputs("package.json", "pnpm-lock.yaml", []string{".npmrc", "pnpm-workspace.yaml"}),
			detectionCapability:    detectionCapability{required: []string{"package.json", "pnpm-lock.yaml"}},
			verificationCapability: verificationCapability{manager: "pnpm"},
			constraintCapability: constraintCapability{
				key: key, detect: detectNodeConstraints,
			},
			toolchainCapability: nodeToolchain(key, "pnpm", "", []string{"pnpm-v6", "pnpm-v9"}, true),
			profilePolicyCapability: profilePolicyCapability{
				expectedScanner: "pnpm", lockFormats: []string{"pnpm-v6", "pnpm-v9"}, versionStyle: "exact",
			},
			scannerCapability: scannerCapability{expectedScanner: "pnpm", resolve: func(request ecosystem.ScannerRequest) (ecosystem.ScannerSpec, error) {
				args := []string{"pnpm", "outdated", "--format", "json"}
				if !request.InstalledTool || request.MinReleaseAgeDays > 0 {
					minimumAge := request.MinReleaseAgeDays
					if request.InstalledTool {
						minimumAge *= 24 * 60
					}
					args = append(args, "--config.minimumReleaseAge="+strconv.Itoa(minimumAge))
				}
				return ecosystem.ScannerSpec{
					Kind: "pnpm", ExpectedScanner: "pnpm", Args: args, Decoder: "pnpm",
					AcceptedExitCodes: []int{1}, ReleaseAge: true, LegacyImageKey: "node",
				}, nil
			}},
			decoderCapability: decoderCapability{kind: "pnpm"},
			changeCapability:  changes("package.json", "pnpm-lock.yaml"),
		},
		mutationCapability: mutationCapability{resolve: func(ecosystem.MutationRequest) (ecosystem.MutationSpec, error) {
			return ecosystem.MutationSpec{
				LockFile: "pnpm-lock.yaml", Commands: [][]string{{"pnpm", "up", "--latest"}},
				LegacyImageKey: "node",
			}, nil
		}},
		plannedMutationCapability: plannedMutationCapability{resolve: func(request ecosystem.PlannedMutationRequest) (ecosystem.PlannedMutationSpec, error) {
			mutations := make([]ecosystem.CandidateMutation, 0, len(request.Candidates))
			for _, candidate := range request.Candidates {
				args := []string{"pnpm", "update", "--lockfile-only"}
				if !request.AllowScripts {
					args = append(args, "--ignore-scripts")
				}
				args = append(args, candidate.Name+"@"+candidate.Target)
				mutations = append(mutations, ecosystem.CandidateMutation{Candidate: candidate, Commands: [][]string{args}})
			}
			return ecosystem.PlannedMutationSpec{
				LockFile: "pnpm-lock.yaml", LegacyImageKey: "node", Mutations: mutations,
			}, nil
		}},
	}
}

// Bun returns the detected but deliberately scanner-unsupported node/bun
// adapter.
func Bun() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "node", PackageManager: "bun"}
	return unsupportedAdapter{
		baseAdapter: base(key, "Bun", 100, false,
			"npm-check-updates cannot use the mandatory egress proxy under Bun; use npm or pnpm until a Bun scanner with stable structured output is available"),
		inputCapability:        inputs("package.json", "bun.lock", []string{".npmrc", "bunfig.toml"}),
		detectionCapability:    detectionCapability{required: []string{"package.json", "bun.lock"}},
		verificationCapability: verificationCapability{manager: "bun"},
		constraintCapability:   constraintCapability{key: key, detect: detectNodeConstraints},
		profilePolicyCapability: profilePolicyCapability{
			expectedScanner: "ncu", lockFormats: []string{"bun-text"}, versionStyle: "exact",
		},
		changeCapability: changes("package.json", "bun.lock"),
	}
}

// Poetry returns the python/poetry built-in adapter.
func Poetry() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "python", PackageManager: "poetry"}
	return mutablePythonAdapter(key, "Poetry", "poetry.lock", "poetry-v2", "poetry", defaultPoetryVersion,
		"python-poetry.Dockerfile", []string{"poetry.toml"},
		func(runtime, manager string) map[string]string {
			return map[string]string{
				"BASE_IMAGE": "python:" + runtime + "-slim-bookworm", "POETRY_VERSION": manager,
			}
		},
		[]string{"poetry", "show", "--outdated", "--format", "json"},
		[][]string{{"poetry", "update"}},
	)
}

// UV returns the python/uv built-in adapter.
func UV() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "python", PackageManager: "uv"}
	return mutablePythonAdapter(key, "uv", "uv.lock", "uv-v1", "uv", defaultUVVersion,
		"python-uv.Dockerfile", nil,
		func(runtime, manager string) map[string]string {
			return map[string]string{
				"BASE_IMAGE": "python:" + runtime + "-slim-bookworm",
				"UV_IMAGE":   "ghcr.io/astral-sh/uv:" + manager,
				"UV_VERSION": manager,
			}
		},
		[]string{"uv", "tree", "--outdated", "--frozen", "--format", "json"},
		[][]string{{"uv", "lock", "--upgrade"}},
	)
}

// PipTools returns the python/pip-tools built-in adapter.
func PipTools() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "python", PackageManager: "pip-tools"}
	adapter := mutablePythonAdapter(key, "pip-tools", "requirements.txt", "requirements",
		"vuelta-pip-tools-scan", defaultPipScanner, "python-pip-tools.Dockerfile", []string{"pip.conf"},
		func(runtime, manager string) map[string]string {
			return map[string]string{
				"BASE_IMAGE":        "python:" + runtime + "-slim-bookworm",
				"PIP_VERSION":       defaultPipVersion,
				"PIP_TOOLS_VERSION": manager,
				"SCANNER_VERSION":   defaultPipScanner,
			}
		},
		[]string{"vuelta-pip-tools-scan", "--requirements", "requirements.in", "--report"},
		[][]string{{"pip-compile", "--upgrade", "requirements.in"}},
	)
	adapter.files = append(adapter.files, ecosystem.InputFile{
		Path: "pyproject.toml", Category: ecosystem.InputCategoryManifest, Optional: true,
	})
	adapter.detect = detectPipToolsConstraints
	return pipToolsAdapter{mutableAdapter: adapter}
}

// Requirements returns the scan-only python/requirements built-in adapter.
func Requirements() ecosystem.Adapter {
	key := ecosystem.Key{Stack: "python", PackageManager: "requirements"}
	files := []ecosystem.InputFile{{Path: "requirements.txt", Category: ecosystem.InputCategoryDependency}}
	return scanningAdapter{
		baseAdapter: base(key, "requirements.txt", 1000, true, ""),
		inputCapability: inputCapability{
			files: files,
		},
		detectionCapability:  detectionCapability{required: []string{"requirements.txt"}},
		constraintCapability: constraintCapability{key: key, detect: detectRequirementsConstraints},
		toolchainCapability: toolchainCapability{resolve: func(constraints ecosystem.Constraints) (ecosystem.ToolchainSpec, error) {
			runtime, err := ecosystem.ResolveRuntime("python", constraints.Runtime, "3.12", []string{"3.12", "3.13", "3.11"})
			if err != nil {
				return ecosystem.ToolchainSpec{}, err
			}
			return ecosystem.ToolchainSpec{
				ID:  "default-python" + strings.ReplaceAll(runtime, ".", "") + "-requirements",
				Key: key, AdapterVersion: adapterVersion, Runtime: runtime,
				PackageManagerVersion: defaultPipVersion,
				Scanner:               "vuelta-pip-tools-scan",
				ScannerVersion:        defaultPipScanner,
				Platform:              constraints.Platform, User: "10001:10001",
				LockFormats:  []string{"requirements-direct"},
				Capabilities: ecosystem.ToolchainCapabilities{ReadOnlyDiscovery: true},
				Dockerfile:   "python-pip-tools.Dockerfile",
				BuildArgs: map[string]string{
					"BASE_IMAGE": "python:" + runtime + "-slim-bookworm", "PIP_VERSION": defaultPipVersion,
					"PIP_TOOLS_VERSION": defaultPipToolsVersion, "SCANNER_VERSION": defaultPipScanner,
				},
			}, nil
		}},
		profilePolicyCapability: profilePolicyCapability{
			expectedScanner: "vuelta-pip-tools-scan", lockFormats: []string{"requirements-direct"}, versionStyle: "exact",
		},
		scannerCapability: scannerCapability{expectedScanner: "vuelta-pip-tools-scan", resolve: func(ecosystem.ScannerRequest) (ecosystem.ScannerSpec, error) {
			return ecosystem.ScannerSpec{
				Kind: "requirements", ExpectedScanner: "vuelta-pip-tools-scan",
				Args:    []string{"vuelta-pip-tools-scan", "--requirements", "requirements.txt", "--report"},
				Decoder: "requirements", LegacyImageKey: "python-pip-tools",
			}, nil
		}},
		decoderCapability: decoderCapability{kind: "requirements"},
		changeCapability:  changes("requirements.txt"),
	}
}

func base(key ecosystem.Key, displayName string, priority int, fallback bool, unsupported string) baseAdapter {
	return baseAdapter{key: key, metadata: ecosystem.Metadata{
		DisplayName: displayName, Version: adapterVersion, DetectionPriority: priority,
		FallbackDetection: fallback, UnsupportedReason: unsupported,
	}}
}

func inputs(manifest, lock string, managerConfigs []string) inputCapability {
	return inputCapability{
		files: []ecosystem.InputFile{
			{Path: manifest, Category: ecosystem.InputCategoryManifest},
			{Path: lock, Category: ecosystem.InputCategoryLock},
		},
		managerConfigs: append([]string(nil), managerConfigs...),
	}
}

func changes(paths ...string) changeCapability {
	return changeCapability{paths: append([]string(nil), paths...)}
}

func mutablePythonAdapter(
	key ecosystem.Key,
	displayName, lockFile, lockFormat, scannerName, scannerVersion, dockerfile string,
	managerConfigs []string,
	buildArgs func(runtime, manager string) map[string]string,
	scannerArgs []string,
	mutationCommands [][]string,
) mutableAdapter {
	manifest := "pyproject.toml"
	detectionFiles := []string{manifest, lockFile}
	if key.PackageManager == "pip-tools" {
		manifest = "requirements.in"
		detectionFiles = []string{manifest}
	}
	return mutableAdapter{
		scanningAdapter: scanningAdapter{
			baseAdapter:         base(key, displayName, 100, false, ""),
			inputCapability:     inputs(manifest, lockFile, managerConfigs),
			detectionCapability: detectionCapability{required: detectionFiles},
			constraintCapability: constraintCapability{
				key: key, detect: detectPythonConstraints,
			},
			toolchainCapability: pythonToolchain(key, lockFormat, scannerName, scannerVersion, dockerfile, buildArgs),
			profilePolicyCapability: profilePolicyCapability{
				expectedScanner: scannerName, lockFormats: []string{lockFormat},
				versionStyle: map[string]string{
					"poetry": "contains-version", "uv": "prefix-name-version", "pip-tools": "exact",
				}[key.PackageManager],
			},
			scannerCapability: scannerCapability{expectedScanner: scannerName, resolve: func(ecosystem.ScannerRequest) (ecosystem.ScannerSpec, error) {
				return ecosystem.ScannerSpec{
					Kind: key.PackageManager, ExpectedScanner: scannerName,
					Args: append([]string(nil), scannerArgs...), Decoder: key.PackageManager,
					LegacyImageKey: "python-" + key.PackageManager,
				}, nil
			}},
			decoderCapability: decoderCapability{kind: key.PackageManager},
			changeCapability:  changes(manifest, lockFile),
		},
		mutationCapability: mutationCapability{resolve: func(ecosystem.MutationRequest) (ecosystem.MutationSpec, error) {
			commands := make([][]string, len(mutationCommands))
			for index := range mutationCommands {
				commands[index] = append([]string(nil), mutationCommands[index]...)
			}
			return ecosystem.MutationSpec{
				LockFile: lockFile, Commands: commands,
				LegacyImageKey: "python-" + key.PackageManager,
			}, nil
		}},
		plannedMutationCapability: plannedMutationCapability{resolve: func(request ecosystem.PlannedMutationRequest) (ecosystem.PlannedMutationSpec, error) {
			spec := ecosystem.PlannedMutationSpec{
				LockFile: lockFile, LegacyImageKey: "python-" + key.PackageManager,
				Mutations: make([]ecosystem.CandidateMutation, 0, len(request.Candidates)),
			}
			for _, candidate := range request.Candidates {
				mutation := ecosystem.CandidateMutation{Candidate: candidate}
				switch key.PackageManager {
				case "poetry":
					mutation.Commands = [][]string{{"poetry", "add", candidate.Name + "==" + candidate.Target}}
				case "uv":
					mutation.Commands = [][]string{{"uv", "add", candidate.Name + "==" + candidate.Target, "--no-sync"}}
				case "pip-tools":
					mutation.Rewrite = "python-requirement-exact-pin"
				}
				spec.Mutations = append(spec.Mutations, mutation)
			}
			if key.PackageManager == "pip-tools" && len(request.Candidates) > 0 {
				spec.FinalCommands = [][]string{{"pip-compile", "requirements.in"}}
			}
			return spec, nil
		}},
	}
}

func nodeToolchain(key ecosystem.Key, scanner, scannerVersion string, lockFormats []string, releaseAge bool) toolchainCapability {
	return toolchainCapability{resolve: func(constraints ecosystem.Constraints) (ecosystem.ToolchainSpec, error) {
		runtime, err := ecosystem.ResolveRuntime("node", constraints.Runtime, "22", []string{"22", "24", "20"})
		if err != nil {
			return ecosystem.ToolchainSpec{}, err
		}
		managerVersion := constraints.PackageManagerVersion
		buildArgs := map[string]string{"BASE_IMAGE": "node:" + runtime + "-bookworm-slim"}
		dockerfile := ""
		switch key.PackageManager {
		case "npm":
			if managerVersion == "" {
				managerVersion = map[string]string{"20": "10.9.2", "22": "10.9.2", "24": "11.4.2"}[runtime]
			}
			dockerfile = "node-ncu.Dockerfile"
			buildArgs["NPM_VERSION"] = managerVersion
			buildArgs["NCU_VERSION"] = defaultNCUVersion
		case "pnpm":
			if managerVersion == "" {
				managerVersion = map[string]string{"pnpm-v6": "8.15.9", "pnpm-v9": "9.15.0"}[constraints.LockFormat]
			}
			scannerVersion = managerVersion
			dockerfile = "node-pnpm.Dockerfile"
			buildArgs["PNPM_VERSION"] = managerVersion
		}
		return ecosystem.ToolchainSpec{
			ID:  "default-node" + runtime + "-" + key.PackageManager,
			Key: key, AdapterVersion: adapterVersion, Runtime: runtime,
			PackageManagerVersion: managerVersion, Scanner: scanner, ScannerVersion: scannerVersion,
			Platform: constraints.Platform, User: "10001:10001", LockFormats: append([]string(nil), lockFormats...),
			Capabilities: ecosystem.ToolchainCapabilities{ReadOnlyDiscovery: true, ReleaseAge: releaseAge},
			Dockerfile:   dockerfile, BuildArgs: buildArgs,
		}, nil
	}}
}

func pythonToolchain(
	key ecosystem.Key,
	lockFormat, scanner, scannerVersion, dockerfile string,
	buildArgs func(runtime, manager string) map[string]string,
) toolchainCapability {
	return toolchainCapability{resolve: func(constraints ecosystem.Constraints) (ecosystem.ToolchainSpec, error) {
		runtime, err := ecosystem.ResolveRuntime("python", constraints.Runtime, "3.12", []string{"3.12", "3.13", "3.11"})
		if err != nil {
			return ecosystem.ToolchainSpec{}, err
		}
		managerVersion := constraints.PackageManagerVersion
		switch key.PackageManager {
		case "poetry":
			managerVersion = defaultIfEmpty(managerVersion, defaultPoetryVersion)
		case "uv":
			managerVersion = defaultIfEmpty(managerVersion, defaultUVVersion)
		case "pip-tools":
			managerVersion = defaultIfEmpty(managerVersion, defaultPipToolsVersion)
		}
		return ecosystem.ToolchainSpec{
			ID:  "default-python" + strings.ReplaceAll(runtime, ".", "") + "-" + key.PackageManager,
			Key: key, AdapterVersion: adapterVersion, Runtime: runtime,
			PackageManagerVersion: managerVersion, Scanner: scanner, ScannerVersion: scannerVersion,
			Platform: constraints.Platform, User: "10001:10001", LockFormats: []string{lockFormat},
			Capabilities: ecosystem.ToolchainCapabilities{ReadOnlyDiscovery: true},
			Dockerfile:   dockerfile, BuildArgs: buildArgs(runtime, managerVersion),
		}, nil
	}}
}

func detectNodeConstraints(root string, key ecosystem.Key, platform string) (ecosystem.Constraints, error) {
	data, err := ecosystem.ReadRootFile(root, "package.json", ecosystem.DefaultManifestLimit)
	if err != nil {
		return ecosystem.Constraints{}, err
	}
	var manifest struct {
		Engines        map[string]string `json:"engines"`
		PackageManager string            `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ecosystem.Constraints{}, fmt.Errorf("parse package.json toolchain metadata: %w", err)
	}
	runtimeConstraint := strings.TrimSpace(manifest.Engines["node"])
	constraints := ecosystem.Constraints{
		Key: key, Platform: platform, Runtime: runtimeConstraint,
		RuntimeConstraintSource: runtimeConstraintSource(runtimeConstraint),
	}
	if manifest.PackageManager != "" {
		family, version, ok := strings.Cut(manifest.PackageManager, "@")
		if !ok || family == "" || version == "" {
			return ecosystem.Constraints{}, fmt.Errorf("package.json packageManager %q must be family@exact-version", manifest.PackageManager)
		}
		if family != key.PackageManager {
			return ecosystem.Constraints{}, fmt.Errorf("package.json packageManager %q conflicts with configured manager %q", family, key.PackageManager)
		}
		constraints.PackageManagerVersion = version
	}
	switch key.PackageManager {
	case "npm":
		project, err := inspectNPMProject(root)
		if err != nil {
			return ecosystem.Constraints{}, err
		}
		if !project.detected || project.lockFile == "" {
			return ecosystem.Constraints{}, errors.New("npm toolchain resolution requires exactly one supported lockfile")
		}
		lock, err := ecosystem.ReadRootFile(root, project.lockFile, ecosystem.DefaultManifestLimit)
		if err != nil {
			return ecosystem.Constraints{}, err
		}
		var metadata struct {
			LockfileVersion int `json:"lockfileVersion"`
		}
		if err := json.Unmarshal(lock, &metadata); err != nil || metadata.LockfileVersion == 0 {
			return ecosystem.Constraints{}, fmt.Errorf("%s has malformed lockfileVersion", project.lockFile)
		}
		constraints.LockFormat = fmt.Sprintf("npm-v%d", metadata.LockfileVersion)
	case "pnpm":
		lock, err := ecosystem.ReadRootFile(root, "pnpm-lock.yaml", ecosystem.DefaultManifestLimit)
		if err != nil {
			return ecosystem.Constraints{}, err
		}
		var metadata struct {
			LockfileVersion any `yaml:"lockfileVersion"`
		}
		if err := yaml.Unmarshal(lock, &metadata); err != nil {
			return ecosystem.Constraints{}, fmt.Errorf("parse pnpm lock metadata: %w", err)
		}
		major := strings.Split(strings.Trim(fmt.Sprint(metadata.LockfileVersion), "'\""), ".")[0]
		if _, err := strconv.Atoi(major); err != nil {
			return ecosystem.Constraints{}, errors.New("pnpm-lock.yaml has malformed lockfileVersion")
		}
		constraints.LockFormat = "pnpm-v" + major
	case "bun":
		if _, err := ecosystem.ReadRootFile(root, "bun.lock", ecosystem.DefaultManifestLimit); err != nil {
			return ecosystem.Constraints{}, err
		}
		constraints.LockFormat = "bun-text"
	}
	return constraints, nil
}

var (
	requiresPythonPattern = regexp.MustCompile(`(?m)^\s*requires-python\s*=\s*["']([^"']+)["']`)
	poetryPythonPattern   = regexp.MustCompile(`(?m)^\s*python\s*=\s*["']([^"']+)["']`)
)

func detectPythonConstraints(root string, key ecosystem.Key, platform string) (ecosystem.Constraints, error) {
	data, err := ecosystem.ReadRootFile(root, "pyproject.toml", ecosystem.DefaultManifestLimit)
	if err != nil {
		return ecosystem.Constraints{}, err
	}
	constraints := ecosystem.Constraints{Key: key, Platform: platform}
	if match := requiresPythonPattern.FindSubmatch(data); match != nil {
		constraints.Runtime = string(match[1])
	} else if match := poetryPythonPattern.FindSubmatch(data); match != nil {
		constraints.Runtime = string(match[1])
	}
	constraints.RuntimeConstraintSource = runtimeConstraintSource(constraints.Runtime)
	lock := map[string]string{"poetry": "poetry.lock", "uv": "uv.lock", "pip-tools": "requirements.txt"}[key.PackageManager]
	if _, err := ecosystem.ReadRootFile(root, lock, ecosystem.DefaultManifestLimit); err != nil {
		return ecosystem.Constraints{}, err
	}
	constraints.LockFormat = map[string]string{
		"poetry": "poetry-v2", "uv": "uv-v1", "pip-tools": "requirements",
	}[key.PackageManager]
	return constraints, nil
}

func detectRequirementsConstraints(root string, key ecosystem.Key, platform string) (ecosystem.Constraints, error) {
	if _, err := ecosystem.ReadRootFile(root, "requirements.txt", ecosystem.DefaultManifestLimit); err != nil {
		return ecosystem.Constraints{}, err
	}
	return ecosystem.Constraints{
		Key: key, Platform: platform, LockFormat: "requirements-direct",
		RuntimeConstraintSource: ecosystem.RuntimeConstraintSourceDefault,
	}, nil
}

func runtimeConstraintSource(runtime string) string {
	if strings.TrimSpace(runtime) == "" {
		return ecosystem.RuntimeConstraintSourceDefault
	}
	return ecosystem.RuntimeConstraintSourceProject
}

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
