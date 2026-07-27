package toolchain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sort"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
)

// Constraints is the allowlisted project metadata used during resolution.
type Constraints struct {
	Stack                 string `json:"stack"`
	PackageManager        string `json:"package_manager"`
	Runtime               string `json:"runtime,omitempty"`
	PackageManagerVersion string `json:"package_manager_version,omitempty"`
	LockFormat            string `json:"lock_format"`
	Platform              string `json:"platform"`
}

// Identity is persisted in snapshots so update cannot silently switch image,
// runtime, scanner, platform, user, lock support, or capability semantics.
type Identity struct {
	AdapterID             string                       `json:"adapter_id,omitempty"`
	AdapterVersion        string                       `json:"adapter_version,omitempty"`
	Source                string                       `json:"source"`
	ProfileID             string                       `json:"profile_id"`
	Hash                  string                       `json:"hash"`
	Runtime               string                       `json:"runtime"`
	PackageManager        string                       `json:"package_manager"`
	PackageManagerVersion string                       `json:"package_manager_version"`
	Scanner               string                       `json:"scanner"`
	ScannerVersion        string                       `json:"scanner_version"`
	Image                 string                       `json:"image"`
	ImageID               string                       `json:"image_id"`
	Platform              string                       `json:"platform"`
	User                  string                       `json:"user"`
	LockFormats           []string                     `json:"lock_formats"`
	Capabilities          config.ToolchainCapabilities `json:"capabilities"`
}

// Resolve selects profile metadata without calling Docker. Scan callers use
// Prepare so embedded defaults are built and pinned to a local image ID.
func Resolve(ws config.Workspace, cfg config.Config) (config.ToolchainProfile, Identity, Constraints, error) {
	constraints, detectErr := Detect(ws)
	if detectErr != nil {
		return config.ToolchainProfile{}, Identity{}, Constraints{}, detectErr
	}
	selection, err := Select(ws, cfg)
	if err != nil {
		return config.ToolchainProfile{}, Identity{}, constraints, err
	}
	identity, err := IdentityForResolvedProfile(selection.Profile, selection.Source, selection.Profile.Image)
	return selection.Profile, identity, selection.Constraints, err
}

// ValidateManagerSupport rejects manager families without a safe structured
// scanner before a project is onboarded or Docker is called.
func ValidateManagerSupport(stack, manager string) error {
	registry, err := catalog.New()
	if err != nil {
		return fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	adapter, err := registry.Lookup(stack, manager)
	if err != nil {
		return err
	}
	if _, ok := adapter.(ecosystem.ScannerProvider); !ok {
		return &ecosystem.CapabilityError{
			Key: adapter.Key(), Capability: "candidate-scanner",
			Reason: adapter.Metadata().UnsupportedReason,
		}
	}
	return nil
}

// IdentityForProfile returns the stable full-contract identity of a profile.
func IdentityForProfile(profile config.ToolchainProfile) (Identity, error) {
	return IdentityForResolvedProfile(profile, SourceOverride, profile.Image)
}

// IdentityForResolvedProfile returns the exact source/image contract persisted
// in snapshots. imageID is a local sha256 ID for defaults and the immutable
// configured image identity for overrides.
func IdentityForResolvedProfile(profile config.ToolchainProfile, source, imageID string) (Identity, error) {
	return identityForResolvedProfile(profile, source, imageID, true)
}

func identityForResolvedProfile(profile config.ToolchainProfile, source, imageID string, bindAdapter bool) (Identity, error) {
	adapterID := ""
	adapterVersion := ""
	if bindAdapter {
		registry, err := catalog.New()
		if err != nil {
			return Identity{}, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
		}
		adapter, err := registry.Lookup(profile.Stack, profile.PackageManager)
		if err != nil {
			return Identity{}, err
		}
		adapterID = adapter.Key().String()
		adapterVersion = adapter.Metadata().Version
	}
	contract := struct {
		Profile        config.ToolchainProfile `json:"profile"`
		AdapterID      string                  `json:"adapter_id,omitempty"`
		AdapterVersion string                  `json:"adapter_version,omitempty"`
		Source         string                  `json:"source"`
		ImageID        string                  `json:"image_id"`
	}{Profile: profile, AdapterID: adapterID, AdapterVersion: adapterVersion, Source: source, ImageID: imageID}
	data, err := json.Marshal(contract)
	if err != nil {
		return Identity{}, fmt.Errorf("encode toolchain profile: %w", err)
	}
	sum := sha256.Sum256(data)
	locks := append([]string(nil), profile.LockFormats...)
	sort.Strings(locks)
	return Identity{
		AdapterID: adapterID, AdapterVersion: adapterVersion,
		Source: source, ProfileID: profile.ID, Hash: fmt.Sprintf("%x", sum), Runtime: profile.Runtime,
		PackageManager: profile.PackageManager, PackageManagerVersion: profile.PackageManagerVersion,
		Scanner: profile.Scanner, ScannerVersion: profile.ScannerVersion, Image: profile.Image, ImageID: imageID,
		Platform: profile.Platform, User: profile.User, LockFormats: locks, Capabilities: profile.Capabilities,
	}, nil
}

// MatchesResolvedIdentity accepts current adapter-bound identities and the
// legacy unbound form only for already-created short-lived snapshots.
func MatchesResolvedIdentity(persisted Identity, profile config.ToolchainProfile, actual Identity) bool {
	if persisted.AdapterID != "" || persisted.AdapterVersion != "" {
		return reflect.DeepEqual(persisted, actual)
	}
	legacy, err := identityForResolvedProfile(profile, actual.Source, actual.ImageID, false)
	return err == nil && reflect.DeepEqual(persisted, legacy)
}

// Detect reads only the selected workspace's supported root manifest and lock
// metadata. It does not inspect parents, manager config, source, or secrets.
func Detect(ws config.Workspace) (Constraints, error) {
	constraints := Constraints{Stack: ws.Stack, PackageManager: ws.PackageManager, Platform: ws.Platform}
	if constraints.Platform == "" {
		if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
			return Constraints{}, fmt.Errorf("host architecture %q has no supported scanner platform", runtime.GOARCH)
		}
		constraints.Platform = "linux/" + runtime.GOARCH
	}
	registry, err := catalog.New()
	if err != nil {
		return Constraints{}, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	adapter, err := registry.Lookup(ws.Stack, ws.PackageManager)
	if err != nil {
		return Constraints{}, err
	}
	detector, ok := adapter.(ecosystem.ConstraintDetector)
	if !ok {
		return Constraints{}, &ecosystem.CapabilityError{Key: adapter.Key(), Capability: "toolchain-constraints"}
	}
	detected, err := detector.DetectConstraints(ws.Path, constraints.Platform)
	if err != nil {
		return Constraints{}, err
	}
	if detected.Key != adapter.Key() {
		return Constraints{}, fmt.Errorf("adapter %s returned constraints for %s", adapter.Key().String(), detected.Key.String())
	}
	return Constraints{
		Stack: detected.Key.Stack, PackageManager: detected.Key.PackageManager,
		Runtime: detected.Runtime, PackageManagerVersion: detected.PackageManagerVersion,
		LockFormat: detected.LockFormat, Platform: detected.Platform,
	}, nil
}

func incompatibility(
	profile config.ToolchainProfile,
	constraints Constraints,
	runtimeConstraint ecosystem.RuntimeConstraint,
) string {
	if profile.Stack != constraints.Stack || profile.PackageManager != constraints.PackageManager {
		return "stack or package manager mismatch"
	}
	if profile.Platform != constraints.Platform {
		return "platform mismatch"
	}
	if !contains(profile.LockFormats, constraints.LockFormat) {
		return "lock format " + constraints.LockFormat + " is unsupported"
	}
	if constraints.PackageManagerVersion != "" && profile.PackageManagerVersion != constraints.PackageManagerVersion {
		return "package manager version mismatch"
	}
	if constraints.Runtime != "" && !runtimeConstraint.MatchesProfile(profile.Runtime) {
		return "runtime constraint " + constraints.Runtime + " is not satisfied"
	}
	if !profile.Capabilities.ReadOnlyDiscovery {
		return "read-only discovery is unsupported"
	}
	return ""
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
