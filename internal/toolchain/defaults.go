package toolchain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
)

const (
	// SourceDefault identifies a profile derived from Vuelta's embedded table.
	SourceDefault = "default"
	// SourceOverride identifies an operator-supplied config profile.
	SourceOverride = "override"
)

var exactVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9.-]+)?$`)

// Selection is a side-effect-free resolution result. Default selections carry
// an embedded build recipe; override selections use the exact configured
// image reference.
type Selection struct {
	Profile           config.ToolchainProfile
	Constraints       Constraints
	RuntimeConstraint string
	Source            string
	build             *buildSpec
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
	runtimeConstraint, err := ecosystem.ParseRuntimeConstraint(constraints.Stack, constraints.Runtime)
	if err != nil {
		return Selection{}, err
	}
	profile, found, err := selectOverride(ws, cfg.Update.ToolchainProfiles, constraints, runtimeConstraint)
	if err != nil {
		return Selection{}, err
	}
	if found {
		return Selection{
			Profile: profile, Constraints: constraints,
			RuntimeConstraint: runtimeConstraint.Canonical(), Source: SourceOverride,
		}, nil
	}
	profile, build, err := defaultProfile(constraints)
	if err != nil {
		return Selection{}, err
	}
	if !runtimeConstraint.MatchesProfile(profile.Runtime) {
		return Selection{}, fmt.Errorf("resolved embedded runtime %q does not satisfy parsed constraint %q", profile.Runtime, runtimeConstraint.Canonical())
	}
	return Selection{
		Profile: profile, Constraints: constraints,
		RuntimeConstraint: runtimeConstraint.Canonical(), Source: SourceDefault, build: &build,
	}, nil
}

func selectOverride(
	ws config.Workspace,
	profiles []config.ToolchainProfile,
	constraints Constraints,
	runtimeConstraint ecosystem.RuntimeConstraint,
) (config.ToolchainProfile, bool, error) {
	var matches []config.ToolchainProfile
	var reasons []string
	selectedIDFound := false
	for _, profile := range profiles {
		if ws.ToolchainProfile != "" && profile.ID != ws.ToolchainProfile {
			continue
		}
		selectedIDFound = selectedIDFound || profile.ID == ws.ToolchainProfile
		if reason := incompatibility(profile, constraints, runtimeConstraint); reason != "" {
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
	registry, err := catalog.New()
	if err != nil {
		return config.ToolchainProfile{}, buildSpec{}, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	adapter, err := registry.Lookup(constraints.Stack, constraints.PackageManager)
	if err != nil {
		return config.ToolchainProfile{}, buildSpec{}, err
	}
	provider, ok := adapter.(ecosystem.ToolchainProvider)
	if !ok {
		return config.ToolchainProfile{}, buildSpec{}, &ecosystem.CapabilityError{
			Key: adapter.Key(), Capability: "default-toolchain",
			Reason: adapter.Metadata().UnsupportedReason,
		}
	}
	spec, err := provider.DefaultToolchain(ecosystem.Constraints{
		Key: adapter.Key(), Runtime: constraints.Runtime,
		PackageManagerVersion: constraints.PackageManagerVersion,
		LockFormat:            constraints.LockFormat, Platform: constraints.Platform,
	})
	if err != nil {
		return config.ToolchainProfile{}, buildSpec{}, err
	}
	if spec.Key != adapter.Key() {
		return config.ToolchainProfile{}, buildSpec{}, fmt.Errorf("adapter %s returned toolchain for %s", adapter.Key().String(), spec.Key.String())
	}
	if !exactVersionPattern.MatchString(spec.PackageManagerVersion) {
		return config.ToolchainProfile{}, buildSpec{}, fmt.Errorf("detected package manager version %q is not an exact supported version; declare family@exact-version or add an override", spec.PackageManagerVersion)
	}
	profile := config.ToolchainProfile{
		Version: config.ToolchainProfileVersion, ID: spec.ID, Stack: spec.Key.Stack,
		PackageManager: spec.Key.PackageManager, Runtime: spec.Runtime,
		PackageManagerVersion: spec.PackageManagerVersion,
		Scanner:               spec.Scanner, ScannerVersion: spec.ScannerVersion,
		Platform: spec.Platform, User: spec.User,
		LockFormats: append([]string(nil), spec.LockFormats...),
		Capabilities: config.ToolchainCapabilities{
			ReadOnlyDiscovery: spec.Capabilities.ReadOnlyDiscovery,
			ReleaseAge:        spec.Capabilities.ReleaseAge,
			ProjectConfig:     spec.Capabilities.ProjectConfig,
		},
	}
	build := buildSpec{Dockerfile: spec.Dockerfile, Args: make(map[string]string, len(spec.BuildArgs))}
	for key, value := range spec.BuildArgs {
		build.Args[key] = value
	}
	return profile, build, nil
}
