package toolchain

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

const (
	// SourceDefault identifies a profile derived from Vuelta's embedded table.
	SourceDefault = "default"
	// SourceOverride identifies an operator-supplied config profile.
	SourceOverride = "override"
)

const (
	defaultNCUVersion      = "22.2.9"
	defaultPoetryVersion   = "2.1.1"
	defaultUVVersion       = "0.6.14"
	defaultPipVersion      = "25.0.1"
	defaultPipToolsVersion = "7.5.0"
	defaultPipScanner      = "1.0.0"
)

var exactVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9.-]+)?$`)

// Selection is a side-effect-free resolution result. Default selections carry
// an embedded build recipe; override selections use the exact configured
// image reference.
type Selection struct {
	Profile     config.ToolchainProfile
	Constraints Constraints
	Source      string
	build       *buildSpec
}

// Select resolves operator overrides first and otherwise derives a supported
// default from allowlisted project metadata. It never calls Docker.
func Select(ws config.Workspace, cfg config.Config) (Selection, error) {
	constraints, err := Detect(ws)
	if err != nil {
		return Selection{}, err
	}
	if err := ValidateManagerSupport(constraints.Stack, constraints.PackageManager); err != nil {
		return Selection{}, err
	}
	profile, found, err := selectOverride(ws, cfg.Update.ToolchainProfiles, constraints)
	if err != nil {
		return Selection{}, err
	}
	if found {
		return Selection{Profile: profile, Constraints: constraints, Source: SourceOverride}, nil
	}
	profile, build, err := defaultProfile(constraints)
	if err != nil {
		return Selection{}, err
	}
	return Selection{Profile: profile, Constraints: constraints, Source: SourceDefault, build: &build}, nil
}

func selectOverride(ws config.Workspace, profiles []config.ToolchainProfile, constraints Constraints) (config.ToolchainProfile, bool, error) {
	var matches []config.ToolchainProfile
	var reasons []string
	selectedIDFound := false
	for _, profile := range profiles {
		if ws.ToolchainProfile != "" && profile.ID != ws.ToolchainProfile {
			continue
		}
		selectedIDFound = selectedIDFound || profile.ID == ws.ToolchainProfile
		if reason := incompatibility(profile, constraints); reason != "" {
			reasons = append(reasons, profile.ID+": "+reason)
			continue
		}
		matches = append(matches, profile)
	}
	if len(matches) == 1 {
		return matches[0], true, nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, profile := range matches {
			ids = append(ids, profile.ID)
		}
		sort.Strings(ids)
		return config.ToolchainProfile{}, false, fmt.Errorf("toolchain constraints are ambiguous; compatible overrides are %s; set workspaces[].toolchain_profile", strings.Join(ids, ", "))
	}
	if ws.ToolchainProfile == "" {
		return config.ToolchainProfile{}, false, nil
	}
	if !selectedIDFound {
		return config.ToolchainProfile{}, false, fmt.Errorf("toolchain override %q is not configured", ws.ToolchainProfile)
	}
	sort.Strings(reasons)
	return config.ToolchainProfile{}, false, fmt.Errorf("toolchain override %q is incompatible with runtime=%q manager=%s@%q lock=%s platform=%s (%s)", ws.ToolchainProfile, constraints.Runtime, constraints.PackageManager, constraints.PackageManagerVersion, constraints.LockFormat, constraints.Platform, strings.Join(reasons, "; "))
}

func defaultProfile(constraints Constraints) (config.ToolchainProfile, buildSpec, error) {
	runtimeVersion, err := defaultRuntime(constraints.Stack, constraints.Runtime)
	if err != nil {
		return config.ToolchainProfile{}, buildSpec{}, err
	}
	managerVersion := constraints.PackageManagerVersion
	profile := config.ToolchainProfile{
		Version: config.ToolchainProfileVersion, Stack: constraints.Stack,
		PackageManager: constraints.PackageManager, Runtime: runtimeVersion,
		Platform: constraints.Platform, User: "10001:10001",
		Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: true},
	}
	build := buildSpec{Args: map[string]string{}}
	switch constraints.Stack + "/" + constraints.PackageManager {
	case "node/npm":
		if managerVersion == "" {
			managerVersion = map[string]string{"20": "10.9.2", "22": "10.9.2", "24": "11.4.2"}[runtimeVersion]
		}
		profile.ID = "default-node" + runtimeVersion + "-npm"
		profile.Scanner, profile.ScannerVersion = "ncu", defaultNCUVersion
		profile.LockFormats = []string{"npm-v2", "npm-v3"}
		profile.Capabilities.ReleaseAge = true
		build.Dockerfile = "node-ncu.Dockerfile"
		build.Args = map[string]string{"BASE_IMAGE": "node:" + runtimeVersion + "-bookworm-slim", "NPM_VERSION": managerVersion, "NCU_VERSION": defaultNCUVersion}
	case "node/pnpm":
		if managerVersion == "" {
			managerVersion = map[string]string{"pnpm-v6": "8.15.9", "pnpm-v9": "9.15.0"}[constraints.LockFormat]
		}
		profile.ID = "default-node" + runtimeVersion + "-pnpm"
		profile.Scanner, profile.ScannerVersion = "pnpm", managerVersion
		profile.LockFormats = []string{"pnpm-v6", "pnpm-v9"}
		profile.Capabilities.ReleaseAge = true
		build.Dockerfile = "node-pnpm.Dockerfile"
		build.Args = map[string]string{"BASE_IMAGE": "node:" + runtimeVersion + "-bookworm-slim", "PNPM_VERSION": managerVersion}
	case "python/poetry":
		managerVersion = defaultIfEmpty(managerVersion, defaultPoetryVersion)
		profile.ID = "default-python" + strings.ReplaceAll(runtimeVersion, ".", "") + "-poetry"
		profile.Scanner, profile.ScannerVersion = "poetry", managerVersion
		profile.LockFormats = []string{"poetry-v2"}
		build.Dockerfile = "python-poetry.Dockerfile"
		build.Args = map[string]string{"BASE_IMAGE": "python:" + runtimeVersion + "-slim-bookworm", "POETRY_VERSION": managerVersion}
	case "python/uv":
		managerVersion = defaultIfEmpty(managerVersion, defaultUVVersion)
		profile.ID = "default-python" + strings.ReplaceAll(runtimeVersion, ".", "") + "-uv"
		profile.Scanner, profile.ScannerVersion = "uv", managerVersion
		profile.LockFormats = []string{"uv-v1"}
		build.Dockerfile = "python-uv.Dockerfile"
		build.Args = map[string]string{"BASE_IMAGE": "python:" + runtimeVersion + "-slim-bookworm", "UV_IMAGE": "ghcr.io/astral-sh/uv:" + managerVersion, "UV_VERSION": managerVersion}
	case "python/pip-tools":
		managerVersion = defaultIfEmpty(managerVersion, defaultPipToolsVersion)
		profile.ID = "default-python" + strings.ReplaceAll(runtimeVersion, ".", "") + "-pip-tools"
		profile.Scanner, profile.ScannerVersion = "vuelta-pip-tools-scan", defaultPipScanner
		profile.LockFormats = []string{"requirements"}
		build.Dockerfile = "python-pip-tools.Dockerfile"
		build.Args = map[string]string{"BASE_IMAGE": "python:" + runtimeVersion + "-slim-bookworm", "PIP_VERSION": defaultPipVersion, "PIP_TOOLS_VERSION": managerVersion, "SCANNER_VERSION": defaultPipScanner}
	default:
		return config.ToolchainProfile{}, buildSpec{}, fmt.Errorf("no embedded default toolchain for %s/%s; add a compatible update.toolchain_profiles override", constraints.Stack, constraints.PackageManager)
	}
	if !exactVersionPattern.MatchString(managerVersion) {
		return config.ToolchainProfile{}, buildSpec{}, fmt.Errorf("detected package manager version %q is not an exact supported version; declare family@exact-version or add an override", managerVersion)
	}
	profile.PackageManagerVersion = managerVersion
	return profile, build, nil
}

func defaultRuntime(stack, constraint string) (string, error) {
	var fallback string
	var supported []string
	switch stack {
	case config.StackNode:
		fallback, supported = "22", []string{"22", "24", "20"}
	case config.StackPython:
		fallback, supported = "3.12", []string{"3.12", "3.13", "3.11"}
	default:
		return "", errors.New("embedded defaults are available only for node and python")
	}
	if strings.TrimSpace(constraint) == "" {
		return fallback, nil
	}
	for _, candidate := range supported {
		if versionMatches(candidate, constraint) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("runtime constraint %q is unsupported; supported %s runtimes are %s; add an update.toolchain_profiles override for an exception", constraint, stack, strings.Join(supported, ", "))
}

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
