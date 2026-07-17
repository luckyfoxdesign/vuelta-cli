// Package toolchain resolves declarative project constraints to one immutable
// scanner/update profile without executing project code.
package toolchain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"gopkg.in/yaml.v3"
)

const manifestLimit = 1 << 20

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
	ProfileID             string                       `json:"profile_id"`
	Hash                  string                       `json:"hash"`
	Runtime               string                       `json:"runtime"`
	PackageManager        string                       `json:"package_manager"`
	PackageManagerVersion string                       `json:"package_manager_version"`
	Scanner               string                       `json:"scanner"`
	ScannerVersion        string                       `json:"scanner_version"`
	Image                 string                       `json:"image"`
	Platform              string                       `json:"platform"`
	User                  string                       `json:"user"`
	LockFormats           []string                     `json:"lock_formats"`
	Capabilities          config.ToolchainCapabilities `json:"capabilities"`
}

// Resolve selects exactly one compatible profile. Ambiguous, conflicting, or
// unsupported metadata fails before Docker is called.
func Resolve(ws config.Workspace, cfg config.Config) (config.ToolchainProfile, Identity, Constraints, error) {
	constraints, err := Detect(ws)
	if err != nil {
		return config.ToolchainProfile{}, Identity{}, Constraints{}, err
	}
	profiles := cfg.Update.ToolchainProfiles
	if len(profiles) == 0 {
		return config.ToolchainProfile{}, Identity{}, constraints, errors.New("no toolchain profiles are configured")
	}
	var matches []config.ToolchainProfile
	var reasons []string
	for _, profile := range profiles {
		if ws.ToolchainProfile != "" && profile.ID != ws.ToolchainProfile {
			continue
		}
		if reason := incompatibility(profile, constraints); reason != "" {
			reasons = append(reasons, profile.ID+": "+reason)
			continue
		}
		matches = append(matches, profile)
	}
	if len(matches) == 0 {
		sort.Strings(reasons)
		selected := "configured profiles"
		if ws.ToolchainProfile != "" {
			selected = "profile " + ws.ToolchainProfile
		}
		details := strings.Join(reasons, "; ")
		if details == "" {
			ids := make([]string, 0, len(profiles))
			for _, profile := range profiles {
				ids = append(ids, profile.ID)
			}
			sort.Strings(ids)
			details = "available profiles: " + strings.Join(ids, ", ")
		}
		return config.ToolchainProfile{}, Identity{}, constraints, fmt.Errorf("no compatible toolchain %s for runtime=%q manager=%s@%q lock=%s platform=%s (%s)", selected, constraints.Runtime, constraints.PackageManager, constraints.PackageManagerVersion, constraints.LockFormat, constraints.Platform, details)
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, profile := range matches {
			ids = append(ids, profile.ID)
		}
		sort.Strings(ids)
		return config.ToolchainProfile{}, Identity{}, constraints, fmt.Errorf("toolchain constraints are ambiguous; compatible profiles are %s; set workspaces[].toolchain_profile", strings.Join(ids, ", "))
	}
	identity, err := IdentityForProfile(matches[0])
	return matches[0], identity, constraints, err
}

// IdentityForProfile returns the stable full-contract identity of a profile.
func IdentityForProfile(profile config.ToolchainProfile) (Identity, error) {
	data, err := json.Marshal(profile)
	if err != nil {
		return Identity{}, fmt.Errorf("encode toolchain profile: %w", err)
	}
	sum := sha256.Sum256(data)
	locks := append([]string(nil), profile.LockFormats...)
	sort.Strings(locks)
	return Identity{
		ProfileID: profile.ID, Hash: fmt.Sprintf("%x", sum), Runtime: profile.Runtime,
		PackageManager: profile.PackageManager, PackageManagerVersion: profile.PackageManagerVersion,
		Scanner: profile.Scanner, ScannerVersion: profile.ScannerVersion, Image: profile.Image,
		Platform: profile.Platform, User: profile.User, LockFormats: locks, Capabilities: profile.Capabilities,
	}, nil
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
	switch ws.Stack + "/" + ws.PackageManager {
	case "node/npm", "node/pnpm", "node/bun":
		if err := detectNode(ws.Path, &constraints); err != nil {
			return Constraints{}, err
		}
	case "python/poetry", "python/uv", "python/pip-tools":
		if err := detectPython(ws.Path, &constraints); err != nil {
			return Constraints{}, err
		}
	default:
		return Constraints{}, fmt.Errorf("no toolchain constraints for %s/%s", ws.Stack, ws.PackageManager)
	}
	return constraints, nil
}

func detectNode(root string, constraints *Constraints) error {
	data, err := readManifest(filepath.Join(root, "package.json"))
	if err != nil {
		return err
	}
	var manifest struct {
		Engines        map[string]string `json:"engines"`
		PackageManager string            `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse package.json toolchain metadata: %w", err)
	}
	constraints.Runtime = strings.TrimSpace(manifest.Engines["node"])
	if manifest.PackageManager != "" {
		family, version, ok := strings.Cut(manifest.PackageManager, "@")
		if !ok || family == "" || version == "" {
			return fmt.Errorf("package.json packageManager %q must be family@exact-version", manifest.PackageManager)
		}
		if family != constraints.PackageManager {
			return fmt.Errorf("package.json packageManager %q conflicts with configured manager %q", family, constraints.PackageManager)
		}
		constraints.PackageManagerVersion = version
	}
	switch constraints.PackageManager {
	case "npm":
		lock, err := readManifest(filepath.Join(root, "package-lock.json"))
		if err != nil {
			return err
		}
		var metadata struct {
			LockfileVersion int `json:"lockfileVersion"`
		}
		if err := json.Unmarshal(lock, &metadata); err != nil || metadata.LockfileVersion == 0 {
			return errors.New("package-lock.json has malformed lockfileVersion")
		}
		constraints.LockFormat = fmt.Sprintf("npm-v%d", metadata.LockfileVersion)
	case "pnpm":
		lock, err := readManifest(filepath.Join(root, "pnpm-lock.yaml"))
		if err != nil {
			return err
		}
		var metadata struct {
			LockfileVersion any `yaml:"lockfileVersion"`
		}
		if err := yaml.Unmarshal(lock, &metadata); err != nil {
			return fmt.Errorf("parse pnpm lock metadata: %w", err)
		}
		major := strings.Split(strings.Trim(fmt.Sprint(metadata.LockfileVersion), "'\""), ".")[0]
		if _, err := strconv.Atoi(major); err != nil {
			return errors.New("pnpm-lock.yaml has malformed lockfileVersion")
		}
		constraints.LockFormat = "pnpm-v" + major
	case "bun":
		if _, err := readManifest(filepath.Join(root, "bun.lock")); err != nil {
			return err
		}
		constraints.LockFormat = "bun-text"
	}
	return nil
}

var (
	requiresPythonPattern = regexp.MustCompile(`(?m)^\s*requires-python\s*=\s*["']([^"']+)["']`)
	poetryPythonPattern   = regexp.MustCompile(`(?m)^\s*python\s*=\s*["']([^"']+)["']`)
)

func detectPython(root string, constraints *Constraints) error {
	data, err := readManifest(filepath.Join(root, "pyproject.toml"))
	if err != nil {
		return err
	}
	if match := requiresPythonPattern.FindSubmatch(data); match != nil {
		constraints.Runtime = string(match[1])
	} else if match := poetryPythonPattern.FindSubmatch(data); match != nil {
		constraints.Runtime = string(match[1])
	}
	lock := map[string]string{"poetry": "poetry.lock", "uv": "uv.lock", "pip-tools": "requirements.txt"}[constraints.PackageManager]
	if _, err := readManifest(filepath.Join(root, lock)); err != nil {
		return err
	}
	constraints.LockFormat = map[string]string{"poetry": "poetry-v2", "uv": "uv-v1", "pip-tools": "requirements"}[constraints.PackageManager]
	return nil
}

func readManifest(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read toolchain metadata %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > manifestLimit {
		return nil, fmt.Errorf("toolchain metadata %s must be a regular file no larger than %d bytes", filepath.Base(path), manifestLimit)
	}
	return os.ReadFile(path)
}

func incompatibility(profile config.ToolchainProfile, constraints Constraints) string {
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
	if constraints.Runtime != "" && !versionMatches(profile.Runtime, constraints.Runtime) {
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

var comparatorPattern = regexp.MustCompile(`(>=|<=|>|<|\^|~|=)?\s*v?([0-9]+(?:\.[0-9]+)?)`)

func versionMatches(version, constraint string) bool {
	actual, ok := numericVersion(version)
	if !ok {
		return false
	}
	for _, alternative := range strings.Split(constraint, "||") {
		matches := comparatorPattern.FindAllStringSubmatch(alternative, -1)
		if len(matches) == 0 {
			continue
		}
		allowed := true
		for _, match := range matches {
			expected, valid := numericVersion(match[2])
			if !valid || !compareVersion(actual, expected, match[1]) {
				allowed = false
				break
			}
		}
		if allowed {
			return true
		}
	}
	return false
}

func numericVersion(value string) ([2]int, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
	if len(parts) == 0 || len(parts) > 2 {
		return [2]int{}, false
	}
	var result [2]int
	for index, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return [2]int{}, false
		}
		result[index] = n
	}
	return result, true
}

func compareVersion(actual, expected [2]int, operator string) bool {
	cmp := 0
	if actual[0] != expected[0] {
		if actual[0] < expected[0] {
			cmp = -1
		} else {
			cmp = 1
		}
	} else if actual[1] != expected[1] {
		if actual[1] < expected[1] {
			cmp = -1
		} else {
			cmp = 1
		}
	}
	switch operator {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "^", "~", "", "=":
		return actual[0] == expected[0] && (strings.Contains(operator, "~") || expected[1] == 0 || actual[1] == expected[1])
	default:
		return false
	}
}
