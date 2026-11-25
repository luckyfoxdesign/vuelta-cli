// Package config strictly loads machine config and the narrow project-owned
// .vuelta.yaml schema. Project paths resolve relative to their config without
// granting project policy control over machine authority.
//
// Validation never walks parent directories or discovers projects; the CLI
// resolver supplies an exact selected root or configured workspace.
package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/gitpath"
	"gopkg.in/yaml.v3"
)

// digestRefPattern matches an image reference pinned to a real sha256 digest,
// e.g. "python:3.12-slim@sha256:<64 hex chars>". It rejects unfilled
// placeholders like "@sha256:<digest>".
var digestRefPattern = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
var projectNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var toolVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9.-]+)?$`)
var containerUserPattern = regexp.MustCompile(`^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$`)

// CurrentSchemaVersion is the only config.yaml schema understood by this
// build. Missing-version legacy configs may be upgraded only through the
// reviewed config migration flow; explicit unsupported versions fail closed.
const CurrentSchemaVersion = 1

var retiredMachineConfigFields = []string{"update.snapshot_state_dir", "notify"}

// RetiredMachineConfigFields lists fields removable only through the reviewed
// config migration flow. Active parsing remains strict and never accepts them.
func RetiredMachineConfigFields() []string {
	return append([]string(nil), retiredMachineConfigFields...)
}

// Config mirrors the config.yaml schema.
type Config struct {
	SchemaVersion    int                    `yaml:"schema_version"`
	Docker           *DockerConfig          `yaml:"docker,omitempty"`
	State            StateConfig            `yaml:"state"`
	VulnScan         VulnScanConfig         `yaml:"vuln_scan"`
	GithubAdvisories GithubAdvisoriesConfig `yaml:"github_advisories"`
	GithubActions    GithubActionsConfig    `yaml:"github_actions"`
	Deploy           DeployConfig           `yaml:"deploy"`
	Update           UpdateConfig           `yaml:"update"`
	Workspaces       []Workspace            `yaml:"workspaces"`
	Git              GitConfig              `yaml:"git"`
}

// StateConfig retains the legacy schema-1 state selector for compatibility.
// No SQLite store is opened by scan or fix.
type StateConfig struct {
	DatabasePath string `yaml:"database_path,omitempty"`
}

// DockerConfig holds the developer-side daemon authority used by scan and
// update.
type DockerConfig struct {
	// Developer is the legacy single-endpoint form; do not combine it with DeveloperEndpoints.
	Developer          *DockerEndpointConfig  `yaml:"developer,omitempty"`
	DeveloperEndpoints []DockerEndpointConfig `yaml:"developer_endpoints,omitempty"`
}

// TrustedDeveloperEndpoints returns the approved endpoints in selection order.
// Validation rejects ambiguous configurations containing both schema forms.
func (c *DockerConfig) TrustedDeveloperEndpoints() []DockerEndpointConfig {
	if c == nil {
		return nil
	}
	if c.Developer != nil {
		return []DockerEndpointConfig{*c.Developer}
	}
	return append([]DockerEndpointConfig(nil), c.DeveloperEndpoints...)
}

// DockerEndpointConfig selects one approved local Unix socket and the daemon
// identity/capabilities expected behind it. It intentionally has no context,
// TCP, TLS, credential-helper, or environment-driven fields.
type DockerEndpointConfig struct {
	Socket         string               `yaml:"socket"`
	ExpectedDaemon DockerDaemonIdentity `yaml:"expected_daemon"`
}

// DockerDaemonIdentity is the reviewed daemon attestation contract.
type DockerDaemonIdentity struct {
	ID                      string   `yaml:"id" json:"id"`
	ServerVersion           string   `yaml:"server_version" json:"server_version"`
	OperatingSystem         string   `yaml:"operating_system" json:"operating_system"`
	Architecture            string   `yaml:"architecture" json:"architecture"`
	MinimumAPIVersion       string   `yaml:"minimum_api_version" json:"minimum_api_version"`
	RequiredSecurityOptions []string `yaml:"required_security_options" json:"required_security_options"`
}

type VulnScanConfig struct {
	// DependencySource selects the only source used for dependency and lock-file
	// findings. Image findings are configured independently below.
	DependencySource    string `yaml:"dependency_source"`
	Image               string `yaml:"image"`
	FailOnSeverity      string `yaml:"fail_on_severity"`
	DatabaseMaxAgeHours int    `yaml:"database_max_age_hours"`
	// PolicyFile is an optional project-relative, tracked YAML file containing
	// time-bounded vulnerability exceptions. Scanner flags must never hide
	// findings, so every exception remains reviewable in Git.
	PolicyFile string          `yaml:"policy_file"`
	ImageScan  ImageScanConfig `yaml:"image_scan"`
}

type ImageScanConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Tool      string   `yaml:"tool"`
	Image     string   `yaml:"image"`
	Platforms []string `yaml:"platforms"`
	VEX       string   `yaml:"vex"`
}

type GithubAdvisoriesConfig struct {
	APIURL   string `yaml:"api_url"`
	TokenEnv string `yaml:"token_env"`
}

// GithubActionsConfig contains machine authority only. Repository and workflow
// identities remain versioned with each workspace.
type GithubActionsConfig struct {
	APIURL            string `yaml:"api_url"`
	TokenEnv          string `yaml:"token_env"`
	ReleaseRepository string `yaml:"release_repository,omitempty"`
	ReleaseWorkflow   string `yaml:"release_workflow,omitempty"`
	ReleaseRef        string `yaml:"release_ref,omitempty"`
	RegistryUser      string `yaml:"registry_user,omitempty"`
}

// DeployConfig contains only global machine-owned safety policy and the
// immutable Vuelta gateway image. Per-project deployment settings are always
// discovered; they are never added to managed repositories.
type DeployConfig struct {
	Enabled         bool   `yaml:"enabled"`
	GatewayImage    string `yaml:"gateway_image,omitempty"`
	DrainSeconds    int    `yaml:"drain_seconds,omitempty"`
	MinFreeMemoryMB int    `yaml:"min_free_memory_mb,omitempty"`
	MinFreeDiskMB   int    `yaml:"min_free_disk_mb,omitempty"`
}

// githubTokenEnvNames is the fixed allowlist for github_advisories.token_env.
// Restricting the variable name keeps a hostile config from routing arbitrary
// environment credentials into an Authorization header.
var githubTokenEnvNames = []string{"GITHUB_TOKEN", "GH_TOKEN", "VUELTA_GITHUB_TOKEN"}

// GithubTokenEnvNames returns the allowed github_advisories.token_env names.
func GithubTokenEnvNames() []string {
	return append([]string(nil), githubTokenEnvNames...)
}

// AllowedGithubTokenEnv reports whether name is an allowed
// github_advisories.token_env variable name.
func AllowedGithubTokenEnv(name string) bool {
	for _, allowed := range githubTokenEnvNames {
		if name == allowed {
			return true
		}
	}
	return false
}

type UpdateConfig struct {
	MinReleaseAgeDays int                `yaml:"min_release_age_days"`
	SnapshotTTLHours  int                `yaml:"snapshot_ttl_hours"`
	Egress            EgressConfig       `yaml:"egress"`
	Images            map[string]string  `yaml:"images,omitempty"`
	Tools             map[string]string  `yaml:"tools,omitempty"`
	ToolchainProfiles []ToolchainProfile `yaml:"toolchain_profiles,omitempty"`
}

const ToolchainProfileVersion = 1

// ToolchainProfile is an explicit operator override for one immutable
// package-manager environment. Embedded defaults are selected automatically;
// overrides can select versions and capabilities but cannot introduce argv or
// shell fragments.
type ToolchainProfile struct {
	Version               int                   `yaml:"version" json:"version"`
	ID                    string                `yaml:"id" json:"id"`
	Stack                 string                `yaml:"stack" json:"stack"`
	PackageManager        string                `yaml:"package_manager" json:"package_manager"`
	Runtime               string                `yaml:"runtime" json:"runtime"`
	PackageManagerVersion string                `yaml:"package_manager_version" json:"package_manager_version"`
	Scanner               string                `yaml:"scanner" json:"scanner"`
	ScannerVersion        string                `yaml:"scanner_version" json:"scanner_version"`
	Image                 string                `yaml:"image" json:"image"`
	Platform              string                `yaml:"platform" json:"platform"`
	User                  string                `yaml:"user" json:"user"`
	LockFormats           []string              `yaml:"lock_formats" json:"lock_formats"`
	Capabilities          ToolchainCapabilities `yaml:"capabilities" json:"capabilities"`
}

// ToolchainCapabilities records security gates the exact image/tool contract
// has been acceptance-tested to implement.
type ToolchainCapabilities struct {
	ReadOnlyDiscovery bool `yaml:"read_only_discovery" json:"read_only_discovery"`
	ReleaseAge        bool `yaml:"release_age" json:"release_age"`
	ProjectConfig     bool `yaml:"project_config" json:"project_config"`
}

// EgressConfig names the checked-in local egress proxy. Update containers join
// only its internal Docker network and receive this proxy as HTTP(S)_PROXY.
// The proxy itself owns the registry allowlist; no bypass mode exists.
type EgressConfig struct {
	Network        string `yaml:"network"`
	ProxyContainer string `yaml:"proxy_container"`
	ProxyURL       string `yaml:"proxy_url"`
	Persistent     bool   `yaml:"persistent,omitempty"`
}

const (
	VerificationVersion  = 1
	VerificationReady    = "ready"
	VerificationScanOnly = "scan_only"
)

// VerificationProfile retains the legacy declarative data schema for one
// workspace. A scan-only workspace is intentionally unable to create an
// update snapshot. Ready profiles contain only bounded argv commands; Compose
// service commands are never inherited as verification commands.
type VerificationProfile struct {
	Version int                `yaml:"version"`
	State   string             `yaml:"state"`
	Steps   []VerificationStep `yaml:"steps,omitempty"`
}

// VerificationStep is one containerized verification command. Command is an
// argv vector, not a shell string. SuccessExitCodes makes success semantics
// explicit instead of relying on a runner default.
type VerificationStep struct {
	Name             string   `yaml:"name"`
	ComposeFile      string   `yaml:"compose_file"`
	Service          string   `yaml:"service"`
	Command          []string `yaml:"command"`
	ScriptBodyHash   string   `yaml:"script_body_hash,omitempty"`
	TimeoutSeconds   int      `yaml:"timeout_seconds"`
	Required         bool     `yaml:"required"`
	SuccessExitCodes []int    `yaml:"success_exit_codes"`
}

// DockerImagesSpec restricts docker-stack analysis to explicit project-relative files.
type DockerImagesSpec struct {
	Files         []string `yaml:"files"`
	RuntimeImages []string `yaml:"runtime_images"`
	Platforms     []string `yaml:"platforms"`
}

type Workspace struct {
	Name             string              `yaml:"name,omitempty"`
	Path             string              `yaml:"path"`
	Stack            string              `yaml:"stack"`
	PackageManager   string              `yaml:"package_manager"`
	ToolchainProfile string              `yaml:"toolchain_profile,omitempty"`
	Platform         string              `yaml:"platform,omitempty"`
	Verification     VerificationProfile `yaml:"verification"`
	Branch           string              `yaml:"branch"`
	Remote           string              `yaml:"remote"`
	// AllowedChangedPaths overrides the legacy config-wide Git allowlist for
	// this workspace. Patterns are normalized repository-relative Git paths:
	// slash is the only separator and *, ?, and [] never match across a slash.
	// Older configs continue to use git.allowed_changed_paths.
	AllowedChangedPaths []string          `yaml:"allowed_changed_paths,omitempty"`
	DockerImages        *DockerImagesSpec `yaml:"docker_images,omitempty"`
	Github              *GithubWorkflow   `yaml:"github,omitempty"`
}

// GithubWorkflow is the narrow repository-owned workflow identity. It cannot
// contain credentials, arbitrary API URLs, or executable text.
type GithubWorkflow struct {
	Repository string `yaml:"repository"`
	Workflow   string `yaml:"workflow"`
}

type GitConfig struct {
	PushMode            string   `yaml:"push_mode"`
	AllowedChangedPaths []string `yaml:"allowed_changed_paths"`
}

// LocalPackagePolicy is the deliberately narrow configuration for an explicit
// adhoc scan. It is loaded from its own file rather than the registered
// workspace configuration, so a local project need not have Git or Docker
// available. It never accepts commands, registries, proxies, or credentials.
type LocalPackagePolicy struct {
	AllowedPackages    []string `yaml:"allowed_packages"`
	MinReleaseAgeDays  int      `yaml:"min_release_age_days"`
	AllowProjectConfig bool     `yaml:"allow_project_config"`
}

const (
	StackPython = "python"
	StackNode   = "node"
	StackDocker = "docker"
)

var localPackageNamePattern = regexp.MustCompile(`^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)

// LoadLocalPackagePolicy reads a standalone local-mode policy. Keeping this
// schema separate prevents local mode from accidentally inheriting a Git,
// Docker, registry, proxy, or notification setting from the regular config.
func LoadLocalPackagePolicy(path string) (LocalPackagePolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LocalPackagePolicy{}, fmt.Errorf("read local package policy %s: %w", path, err)
	}
	var policy LocalPackagePolicy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		return LocalPackagePolicy{}, fmt.Errorf("parse local package policy %s: %w", path, err)
	}
	if err := policy.Validate(); err != nil {
		return LocalPackagePolicy{}, err
	}
	return policy, nil
}

// Validate rejects an empty allowlist and values which could be interpreted as
// package-manager flags. Package names are exact allowlist entries.
func (p LocalPackagePolicy) Validate() error {
	if len(p.AllowedPackages) == 0 {
		return errors.New("local package policy: allowed_packages is required")
	}
	if p.MinReleaseAgeDays < 0 {
		return errors.New("local package policy: min_release_age_days must not be negative")
	}
	seen := make(map[string]bool, len(p.AllowedPackages))
	for _, name := range p.AllowedPackages {
		if !localPackageNamePattern.MatchString(name) || strings.HasPrefix(name, "-") || seen[name] {
			return fmt.Errorf("local package policy: invalid or duplicate allowed package %q", name)
		}
		seen[name] = true
	}
	return nil
}

// Load reads and parses the config file at path. It does not validate.
func Load(path string) (*Config, error) {
	data, _, err := ReadSecureFile(path)
	if err != nil {
		return nil, err
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	return cfg, nil
}

// SchemaVersionError reports a missing or unsupported top-level schema
// version. A missing version can be handled by the reviewed migration flow;
// explicit unsupported versions must never be rewritten automatically.
type SchemaVersionError struct {
	Found *int
}

func (e *SchemaVersionError) Error() string {
	found := "is missing"
	if e.Found != nil {
		found = fmt.Sprintf("%d is unsupported", *e.Found)
	}
	return fmt.Sprintf(
		"config schema_version %s (supported: %d); run `vuelta config migrate --config PATH`",
		found, CurrentSchemaVersion,
	)
}

// Parse decodes config bytes with the same safe defaults and strict field
// checking as Load, without reading from the filesystem.
func Parse(data []byte) (*Config, error) {
	var header struct {
		SchemaVersion *int `yaml:"schema_version"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return nil, err
	}
	if header.SchemaVersion == nil || *header.SchemaVersion != CurrentSchemaVersion {
		return nil, &SchemaVersionError{Found: header.SchemaVersion}
	}

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown keys, e.g. an arbitrary shell "cmd" smuggled into a verification profile

	cfg := Config{Update: UpdateConfig{MinReleaseAgeDays: 14, SnapshotTTLHours: 24}}
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// WorkspaceName returns the persistent name when present and the legacy
// basename fallback otherwise. Loading an old config never writes this value
// back to disk.
func WorkspaceName(ws Workspace) string {
	if ws.Name != "" {
		return ws.Name
	}
	return filepath.Base(filepath.Clean(ws.Path))
}

// WorkspaceWarnings reports lazy-migration warnings for unnamed workspaces.
func (c *Config) WorkspaceWarnings() []string {
	warnings := make([]string, 0)
	for i, ws := range c.Workspaces {
		if ws.Name == "" {
			warnings = append(warnings, fmt.Sprintf("workspaces[%d] has no name; using %q from the path without rewriting the config", i, WorkspaceName(ws)))
		}

	}
	return warnings
}

// VerificationProfileHash returns the stable identity stored in update
// snapshots. It deliberately excludes the workspace path and update policy so
// profile drift can be diagnosed independently.
func VerificationProfileHash(ws Workspace) (string, error) {
	data, err := json.Marshal(ws.Verification)
	if err != nil {
		return "", fmt.Errorf("encode verification profile: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// VerificationDependencyWorkspace derives the one package-manager contract
// actually invoked by approved verification argv. This keeps hybrid
// Docker-owned workspaces tied to their Node manifest, lockfile, platform,
// and toolchain without changing which ecosystem owns update candidates.
func VerificationDependencyWorkspace(ws Workspace) (Workspace, bool, error) {
	registry, err := catalog.New()
	if err != nil {
		return Workspace{}, false, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	var selected ecosystem.Adapter
	for _, step := range ws.Verification.Steps {
		for _, adapter := range registry.Adapters() {
			verification, ok := adapter.(ecosystem.VerificationProvider)
			if !ok {
				continue
			}
			if _, ok := adapter.(ecosystem.VerificationDependencyProvider); !ok {
				continue
			}
			if _, matched := verification.VerificationScript(step.Command); !matched {
				continue
			}
			if selected != nil && selected.Key() != adapter.Key() {
				return Workspace{}, false, errors.New("verification dependency package manager is ambiguous")
			}
			selected = adapter
		}
	}
	if selected == nil {
		return ws, false, nil
	}
	derived := ws
	derived.Stack = selected.Key().Stack
	derived.PackageManager = selected.Key().PackageManager
	return derived, true, nil
}

// VerificationPlan returns a concise, non-shell rendering for CLI output.
func VerificationPlan(ws Workspace) []string {
	if ws.Verification.State == VerificationScanOnly {
		return []string{"scan_only: updates are disabled until verification steps are configured"}
	}
	plan := make([]string, 0, len(ws.Verification.Steps))
	for _, step := range ws.Verification.Steps {
		plan = append(plan, fmt.Sprintf("%s: %s/%s argv=%q timeout=%ds required=%t success=%v", step.Name, step.ComposeFile, step.Service, step.Command, step.TimeoutSeconds, step.Required, step.SuccessExitCodes))
	}
	return plan
}

// AllowedChangedPaths returns the workspace-scoped allowlist when present,
// falling back to the config-wide field used by older configurations.
func (c Config) AllowedChangedPaths(ws Workspace) []string {
	if len(ws.AllowedChangedPaths) > 0 {
		return ws.AllowedChangedPaths
	}
	return c.Git.AllowedChangedPaths
}

// Validate checks the loaded config against the invariants in the spec:
// every workspace path must exist, stack/package_manager
// pairs must be valid, image references must be pinned by digest, the git
// allowlist must be present for every configured workspace, and
// docker_images.files must stay inside the project directory as plain files.
func (c *Config) Validate() error {
	var errs []error
	profiles := make(map[string]ToolchainProfile, len(c.Update.ToolchainProfiles))
	for i, profile := range c.Update.ToolchainProfiles {
		errs = append(errs, validateToolchainProfile(i, profile)...)
		if previous, ok := profiles[profile.ID]; ok {
			errs = append(errs, fmt.Errorf("update.toolchain_profiles[%d].id: %q duplicates profile for %s/%s", i, profile.ID, previous.Stack, previous.PackageManager))
		} else if profile.ID != "" {
			profiles[profile.ID] = profile
		}
	}

	seenNames := make(map[string]int, len(c.Workspaces))
	seenPaths := make(map[string]int, len(c.Workspaces))
	for i, ws := range c.Workspaces {
		errs = append(errs, validateWorkspace(i, ws)...)
		if ws.ToolchainProfile != "" {
			profile, ok := profiles[ws.ToolchainProfile]
			if !ok {
				errs = append(errs, fmt.Errorf("workspaces[%d].toolchain_profile: %q is not in update.toolchain_profiles", i, ws.ToolchainProfile))
			} else if profile.Stack != ws.Stack || profile.PackageManager != ws.PackageManager {
				errs = append(errs, fmt.Errorf("workspaces[%d].toolchain_profile: %q is for %s/%s, not %s/%s", i, profile.ID, profile.Stack, profile.PackageManager, ws.Stack, ws.PackageManager))
			}
		}
		for j, pattern := range ws.AllowedChangedPaths {
			if err := gitpath.ValidatePattern(pattern); err != nil {
				errs = append(errs, fmt.Errorf("workspaces[%d].allowed_changed_paths[%d]: %w", i, j, err))
			}
		}
		name := WorkspaceName(ws)
		if previous, ok := seenNames[name]; ok {
			errs = append(errs, fmt.Errorf("workspaces[%d].name: %q duplicates workspaces[%d]", i, name, previous))
		} else {
			seenNames[name] = i
		}
		canonical, err := canonicalWorkspacePath(ws.Path)
		if err == nil {
			if previous, ok := seenPaths[canonical]; ok {
				errs = append(errs, fmt.Errorf("workspaces[%d].path: canonical path %q duplicates workspaces[%d]", i, canonical, previous))
			} else {
				seenPaths[canonical] = i
			}
		}
	}
	for i, pattern := range c.Git.AllowedChangedPaths {
		if err := gitpath.ValidatePattern(pattern); err != nil {
			errs = append(errs, fmt.Errorf("git.allowed_changed_paths[%d]: %w", i, err))
		}
	}

	for name, ref := range c.Update.Images {
		if !digestRefPattern.MatchString(ref) {
			errs = append(errs, fmt.Errorf("update.images[%s]: %q is not pinned to a digest (expected an ...@sha256:<64 hex chars> reference)", name, ref))
		}
	}

	errs = append(errs, validateEgress(c.Update.Egress)...)
	if c.Docker != nil {
		errs = append(errs, validateDeveloperDocker(c.Docker)...)
	}
	if c.Update.MinReleaseAgeDays < 14 {
		errs = append(errs, errors.New("update.min_release_age_days: must be at least the machine safety default of 14"))
	}
	if c.Update.SnapshotTTLHours != 0 && (c.Update.SnapshotTTLHours < 1 || c.Update.SnapshotTTLHours > 168) {
		errs = append(errs, errors.New("update.snapshot_ttl_hours: must be between 1 and 168"))
	}
	if len(c.Workspaces) > 0 && len(c.Git.AllowedChangedPaths) == 0 {
		missingAllowlist := false
		for _, ws := range c.Workspaces {
			if len(ws.AllowedChangedPaths) == 0 {
				missingAllowlist = true
				break
			}
		}
		if missingAllowlist {
			errs = append(errs, errors.New("git.allowed_changed_paths: allowlist is required, otherwise every update is rolled back for manual review"))
		}
	}

	errs = append(errs, validateSecurityConfig(*c)...)
	errs = append(errs, validateGithubActionsConfig(c.GithubActions)...)
	errs = append(errs, validateDeployConfig(c.Deploy)...)
	errs = append(errs, validateDeployAuthority(c.Deploy, c.GithubActions)...)
	if c.State.DatabasePath != "" && (!filepath.IsAbs(c.State.DatabasePath) || filepath.Clean(c.State.DatabasePath) != c.State.DatabasePath) {
		errs = append(errs, errors.New("state.database_path: must be a clean absolute path when configured"))
	}
	if c.Git.PushMode != "" && c.Git.PushMode != "review_branch" && c.Git.PushMode != "direct_branch" {
		errs = append(errs, fmt.Errorf("git.push_mode: %q is not supported (review_branch|direct_branch)", c.Git.PushMode))
	}

	return errors.Join(errs...)
}

func validateToolchainProfile(index int, profile ToolchainProfile) []error {
	label := fmt.Sprintf("update.toolchain_profiles[%d]", index)
	var errs []error
	if profile.Version != ToolchainProfileVersion {
		errs = append(errs, fmt.Errorf("%s.version: must be %d", label, ToolchainProfileVersion))
	}
	if !projectNamePattern.MatchString(profile.ID) {
		errs = append(errs, fmt.Errorf("%s.id: must be a stable alphanumeric profile ID", label))
	}
	adapter, adapterErr := builtInAdapter(profile.Stack, profile.PackageManager)
	if adapterErr != nil || profile.Stack == StackDocker {
		errs = append(errs, fmt.Errorf("%s: unsupported stack/package_manager %q/%q", label, profile.Stack, profile.PackageManager))
	}
	if !toolVersionPattern.MatchString(profile.Runtime) {
		errs = append(errs, fmt.Errorf("%s.runtime: must be an exact numeric version", label))
	}
	if !toolVersionPattern.MatchString(profile.PackageManagerVersion) {
		errs = append(errs, fmt.Errorf("%s.package_manager_version: must be exact", label))
	}
	if profile.Scanner == "" || !projectNamePattern.MatchString(profile.Scanner) || !toolVersionPattern.MatchString(profile.ScannerVersion) {
		errs = append(errs, fmt.Errorf("%s.scanner: name and exact scanner_version are required", label))
	} else if policy, ok := adapter.(ecosystem.ProfilePolicyProvider); ok && profile.Scanner != policy.ProfilePolicy().ExpectedScanner {
		errs = append(errs, fmt.Errorf("%s.scanner: must be %q for package manager %q", label, policy.ProfilePolicy().ExpectedScanner, profile.PackageManager))
	}
	if !digestRefPattern.MatchString(profile.Image) {
		errs = append(errs, fmt.Errorf("%s.image: %q is not pinned to an exact digest", label, profile.Image))
	}
	if profile.Platform != "linux/amd64" && profile.Platform != "linux/arm64" {
		errs = append(errs, fmt.Errorf("%s.platform: must be linux/amd64 or linux/arm64", label))
	}
	if !containerUserPattern.MatchString(profile.User) {
		errs = append(errs, fmt.Errorf("%s.user: must be an explicit non-root numeric uid:gid", label))
	}
	allowedLocks := make(map[string]bool)
	if policy, ok := adapter.(ecosystem.ProfilePolicyProvider); ok {
		for _, format := range policy.ProfilePolicy().AllowedLockFormats {
			allowedLocks[format] = true
		}
	}
	if len(profile.LockFormats) == 0 {
		errs = append(errs, fmt.Errorf("%s.lock_formats: at least one format is required", label))
	}
	seenLocks := make(map[string]bool, len(profile.LockFormats))
	for _, format := range profile.LockFormats {
		if !allowedLocks[format] || seenLocks[format] {
			errs = append(errs, fmt.Errorf("%s.lock_formats: unsupported or duplicate format %q", label, format))
		}
		seenLocks[format] = true
	}
	if !profile.Capabilities.ReadOnlyDiscovery {
		errs = append(errs, fmt.Errorf("%s.capabilities.read_only_discovery: must be true", label))
	}
	return errs
}

var githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var githubWorkflowPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml$`)

func validateGithubActionsConfig(c GithubActionsConfig) []error {
	var errs []error
	if c.TokenEnv != "" && !AllowedGithubTokenEnv(c.TokenEnv) {
		errs = append(errs, fmt.Errorf("github_actions.token_env: %q is not an allowed token variable (%s)", c.TokenEnv, strings.Join(githubTokenEnvNames, "|")))
	}
	if c.APIURL != "" {
		u, err := url.Parse(c.APIURL)
		switch {
		case err != nil || u.Scheme != "https" || u.Hostname() == "":
			errs = append(errs, errors.New("github_actions.api_url: must be an https URL with a host"))
		case u.User != nil:
			errs = append(errs, errors.New("github_actions.api_url: must not contain userinfo credentials"))
		case u.Port() != "" && u.Port() != "443":
			errs = append(errs, errors.New("github_actions.api_url: must use the default https port"))
		case u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, errors.New("github_actions.api_url: must not contain a query or fragment"))
		}
	}
	if (c.ReleaseRepository == "") != (c.ReleaseWorkflow == "") {
		errs = append(errs, errors.New("github_actions: release_repository and release_workflow must be configured together"))
	}
	if c.ReleaseRepository != "" &&
		(!githubRepositoryPattern.MatchString(c.ReleaseRepository) || strings.Contains(c.ReleaseRepository, "..")) {
		errs = append(errs, errors.New("github_actions.release_repository: must be one exact owner/repository identifier"))
	}
	if c.ReleaseWorkflow != "" &&
		(!githubWorkflowPattern.MatchString(c.ReleaseWorkflow) || strings.Contains(c.ReleaseWorkflow, "..")) {
		errs = append(errs, errors.New("github_actions.release_workflow: must be one workflow YAML filename"))
	}
	if c.ReleaseRepository != "" {
		if c.ReleaseRef == "" {
			errs = append(errs, errors.New("github_actions.release_ref: is required with the central release workflow"))
		} else if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`).MatchString(c.ReleaseRef) ||
			strings.Contains(c.ReleaseRef, "..") || strings.Contains(c.ReleaseRef, "//") {
			errs = append(errs, errors.New("github_actions.release_ref: is invalid"))
		}
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).MatchString(c.RegistryUser) {
			errs = append(errs, errors.New("github_actions.registry_user: is required and invalid"))
		}
	} else if c.ReleaseRef != "" || c.RegistryUser != "" {
		errs = append(errs, errors.New("github_actions: release_ref and registry_user require release_repository"))
	}
	return errs
}

func validateDeployConfig(c DeployConfig) []error {
	var errs []error
	if c.Enabled && !digestRefPattern.MatchString(c.GatewayImage) {
		errs = append(errs, errors.New("deploy.gateway_image: an exact digest-pinned image is required when deploy is enabled"))
	}
	if c.DrainSeconds != 0 && (c.DrainSeconds < 5 || c.DrainSeconds > 300) {
		errs = append(errs, errors.New("deploy.drain_seconds: must be between 5 and 300"))
	}
	if c.MinFreeMemoryMB != 0 && (c.MinFreeMemoryMB < 128 || c.MinFreeMemoryMB > 1<<20) {
		errs = append(errs, errors.New("deploy.min_free_memory_mb: must be between 128 and 1048576"))
	}
	if c.MinFreeDiskMB != 0 && (c.MinFreeDiskMB < 256 || c.MinFreeDiskMB > 1<<24) {
		errs = append(errs, errors.New("deploy.min_free_disk_mb: must be between 256 and 16777216"))
	}
	return errs
}

func validateDeployAuthority(deploy DeployConfig, github GithubActionsConfig) []error {
	if !deploy.Enabled {
		return nil
	}
	if github.ReleaseRepository == "" || github.ReleaseWorkflow == "" ||
		github.ReleaseRef == "" || github.RegistryUser == "" {
		return []error{errors.New("deploy.enabled: central github_actions release repository, workflow, ref, and registry_user are required")}
	}
	return nil
}

// SnapshotTTL returns the validated lifetime of a package update plan.
func (c Config) SnapshotTTL() time.Duration {
	if c.Update.SnapshotTTLHours == 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.Update.SnapshotTTLHours) * time.Hour
}

// SnapshotPolicyHash fingerprints only update-relevant, non-secret policy.
// Notification credentials and GitHub token configuration are deliberately
// excluded so snapshots never become a side channel for those values.
func (c Config) SnapshotPolicyHash(ws Workspace) (string, error) {
	policy := struct {
		Workspace           Workspace
		MinReleaseAgeDays   int
		Egress              EgressConfig
		Images              map[string]string
		Tools               map[string]string
		ToolchainProfiles   []ToolchainProfile
		AllowedChangedPaths []string
	}{ws, c.Update.MinReleaseAgeDays, c.Update.Egress, c.Update.Images, c.Update.Tools, c.Update.ToolchainProfiles, c.AllowedChangedPaths(ws)}
	data, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode snapshot policy: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

func validateEgress(c EgressConfig) []error {
	var errs []error
	namePattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	if !namePattern.MatchString(c.Network) {
		errs = append(errs, errors.New("update.egress.network: required and must be a Docker network name"))
	}
	if !namePattern.MatchString(c.ProxyContainer) {
		errs = append(errs, errors.New("update.egress.proxy_container: required and must be a Docker container name"))
	}
	u, err := url.Parse(c.ProxyURL)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, errors.New("update.egress.proxy_url: must be a plain http://host:port proxy URL without credentials"))
	} else if u.Hostname() != c.ProxyContainer || u.Port() != "3128" {
		errs = append(errs, errors.New("update.egress.proxy_url: host must match proxy_container and port must be 3128"))
	}
	return errs
}

func validateDeveloperDocker(c *DockerConfig) []error {
	var errs []error
	if c.Developer != nil && c.DeveloperEndpoints != nil {
		errs = append(errs, errors.New("docker: developer and developer_endpoints cannot be combined"))
	}
	if len(c.DeveloperEndpoints) > 16 {
		errs = append(errs, errors.New("docker.developer_endpoints: at most 16 trusted endpoints are allowed"))
	}
	errs = append(errs, validateDockerEndpoint("docker.developer", c.Developer, false)...)
	seen := make(map[string]bool)
	for i := range c.DeveloperEndpoints {
		endpoint := &c.DeveloperEndpoints[i]
		label := fmt.Sprintf("docker.developer_endpoints[%d]", i)
		errs = append(errs, validateDockerEndpoint(label, endpoint, false)...)
		socket := filepath.Clean(endpoint.Socket)
		if seen[socket] {
			errs = append(errs, fmt.Errorf("%s.socket: duplicate trusted socket", label))
		}
		seen[socket] = true
	}
	return errs
}

func validateDockerEndpoint(label string, endpoint *DockerEndpointConfig, required bool) []error {
	if endpoint == nil {
		if required {
			return []error{fmt.Errorf("%s: an explicit deploy Docker endpoint is required", label)}
		}
		return nil
	}
	var errs []error
	if !filepath.IsAbs(endpoint.Socket) || strings.ContainsRune(endpoint.Socket, '\x00') {
		errs = append(errs, fmt.Errorf("%s.socket: must be an absolute local Unix socket path", label))
	}
	identity := endpoint.ExpectedDaemon
	for field, value := range map[string]string{
		"id": identity.ID, "server_version": identity.ServerVersion,
		"operating_system": identity.OperatingSystem, "architecture": identity.Architecture,
	} {
		if strings.TrimSpace(value) == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			errs = append(errs, fmt.Errorf("%s.expected_daemon.%s: a bounded exact value is required", label, field))
		}
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(identity.MinimumAPIVersion) {
		errs = append(errs, fmt.Errorf("%s.expected_daemon.minimum_api_version: major.minor is required", label))
	}
	if len(identity.RequiredSecurityOptions) == 0 {
		errs = append(errs, fmt.Errorf("%s.expected_daemon.required_security_options: at least one exact option is required", label))
	}
	seen := make(map[string]bool, len(identity.RequiredSecurityOptions))
	for i, option := range identity.RequiredSecurityOptions {
		if strings.TrimSpace(option) == "" || len(option) > 256 || strings.ContainsAny(option, "\r\n\x00") || seen[option] {
			errs = append(errs, fmt.Errorf("%s.expected_daemon.required_security_options[%d]: must be a unique bounded exact option", label, i))
		}
		seen[option] = true
	}
	return errs
}

func validateSecurityConfig(c Config) []error {
	var errs []error
	switch c.VulnScan.DependencySource {
	case "trivy", "osv-scanner":
		if !digestRefPattern.MatchString(c.VulnScan.Image) {
			errs = append(errs, fmt.Errorf("vuln_scan.image: %q is not pinned to a digest (expected an ...@sha256:<64 hex chars> reference)", c.VulnScan.Image))
		}
	case "github-dependabot":
		if c.VulnScan.Image != "" {
			errs = append(errs, errors.New("vuln_scan.image: must be empty when dependency_source is github-dependabot; use vuln_scan.image_scan.image for image scanning"))
		}
		errs = append(errs, validateGithubAdvisories(c.GithubAdvisories)...)
	default:
		errs = append(errs, fmt.Errorf("vuln_scan.dependency_source: %q is not supported (trivy|osv-scanner|github-dependabot)", c.VulnScan.DependencySource))
	}
	if severityRank(c.VulnScan.FailOnSeverity) < 1 {
		errs = append(errs, fmt.Errorf("vuln_scan.fail_on_severity: %q is not supported (CRITICAL|HIGH|MEDIUM|LOW)", c.VulnScan.FailOnSeverity))
	}
	if c.VulnScan.DatabaseMaxAgeHours <= 0 {
		errs = append(errs, errors.New("vuln_scan.database_max_age_hours: must be positive"))
	}
	if c.VulnScan.ImageScan.Enabled && c.VulnScan.ImageScan.Tool != "trivy" {
		errs = append(errs, errors.New("vuln_scan.image_scan.tool: must be trivy"))
	}
	if c.VulnScan.ImageScan.Enabled && !digestRefPattern.MatchString(c.VulnScan.ImageScan.Image) {
		errs = append(errs, fmt.Errorf("vuln_scan.image_scan.image: %q is not pinned to a digest (expected an ...@sha256:<64 hex chars> reference)", c.VulnScan.ImageScan.Image))
	}
	return errs
}

// validateGithubAdvisories rejects api_url values that could redirect a
// GitHub token to an unapproved destination. Errors never echo the raw URL,
// which could embed credentials in userinfo.
func validateGithubAdvisories(c GithubAdvisoriesConfig) []error {
	var errs []error
	if c.APIURL != "" {
		u, err := url.Parse(c.APIURL)
		switch {
		case err != nil || u.Scheme != "https" || u.Hostname() == "":
			errs = append(errs, errors.New("github_advisories.api_url: must be an https URL with a host"))
		case u.User != nil:
			errs = append(errs, errors.New("github_advisories.api_url: must not contain userinfo credentials"))
		case u.Port() != "" && u.Port() != "443":
			errs = append(errs, errors.New("github_advisories.api_url: must use the default https port"))
		case u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, errors.New("github_advisories.api_url: must not contain a query or fragment"))
		}
	}
	if c.TokenEnv != "" && !AllowedGithubTokenEnv(c.TokenEnv) {
		errs = append(errs, fmt.Errorf("github_advisories.token_env: %q is not an allowed token variable (%s)", c.TokenEnv, strings.Join(githubTokenEnvNames, "|")))
	}
	return errs
}

func severityRank(value string) int {
	switch strings.ToUpper(value) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 0
	}
}

func validateWorkspace(i int, ws Workspace) []error {
	return validateWorkspaceWithOptions(i, ws, false)
}

func validateWorkspaceWithOptions(i int, ws Workspace, allowScriptDrift bool) []error {
	var errs []error
	label := fmt.Sprintf("workspaces[%d]", i)
	if ws.Name != "" && !projectNamePattern.MatchString(ws.Name) {
		errs = append(errs, fmt.Errorf("%s.name: must start with an alphanumeric character and contain only letters, digits, dot, underscore, or hyphen", label))
	}
	if ws.ToolchainProfile != "" && !projectNamePattern.MatchString(ws.ToolchainProfile) {
		errs = append(errs, fmt.Errorf("%s.toolchain_profile: must be a stable profile ID", label))
	}
	if ws.Platform != "" && ws.Platform != "linux/amd64" && ws.Platform != "linux/arm64" {
		errs = append(errs, fmt.Errorf("%s.platform: must be linux/amd64 or linux/arm64", label))
	}
	if ws.Github != nil {
		if !githubRepositoryPattern.MatchString(ws.Github.Repository) || strings.HasPrefix(ws.Github.Repository, ".") ||
			strings.Contains(ws.Github.Repository, "..") {
			errs = append(errs, fmt.Errorf("%s.github.repository: must be an exact owner/repository identifier", label))
		}
		if !githubWorkflowPattern.MatchString(ws.Github.Workflow) || strings.Contains(ws.Github.Workflow, "..") {
			errs = append(errs, fmt.Errorf("%s.github.workflow: must be one workflow filename such as vuelta-update.yml", label))
		}
	}

	if ws.Path == "" {
		errs = append(errs, fmt.Errorf("%s.path: required", label))
		return errs
	}

	info, err := os.Stat(ws.Path)
	if err != nil {
		errs = append(errs, fmt.Errorf("%s.path %s: %w", label, ws.Path, err))
		return errs
	}
	if !info.IsDir() {
		errs = append(errs, fmt.Errorf("%s.path %s: not a directory", label, ws.Path))
		return errs
	}

	stackSupported := ws.Stack == StackDocker
	if !stackSupported {
		registry, err := catalog.New()
		stackSupported = err == nil && len(registry.PackageManagers(ws.Stack)) > 0
	}
	if !stackSupported {
		errs = append(errs, fmt.Errorf("%s.stack: %q is not a supported stack (python|node|docker)", label, ws.Stack))
	} else if ws.Stack == StackDocker {
		if ws.PackageManager != "" {
			errs = append(errs, fmt.Errorf("%s.package_manager: docker stack has no package manager", label))
		}
	} else if ws.Stack == StackPython && ws.PackageManager == "" && ws.Verification.State == VerificationScanOnly {
		// A scan-only Python workspace may expose a root requirements.txt to
		// scanners without claiming that pip-tools owns it. This legacy form is
		// retained until the explicit config-schema migration.
	} else if _, err := builtInAdapter(ws.Stack, ws.PackageManager); err != nil {
		errs = append(errs, fmt.Errorf("%s.package_manager: %q is not valid for stack %q", label, ws.PackageManager, ws.Stack))
	}
	if adapter, err := builtInAdapter(ws.Stack, ws.PackageManager); err == nil {
		if _, mutable := adapter.(ecosystem.MutationProvider); !mutable && adapter.Metadata().UnsupportedReason == "" && ws.Verification.State != VerificationScanOnly {
			errs = append(errs, fmt.Errorf("%s.verification.state: %s has no safe mutation contract and must be scan_only", label, adapter.Key().String()))
		}
	}

	errs = append(errs, validateVerificationProfileWithOptions(label, ws, allowScriptDrift)...)

	if ws.Stack == StackDocker && ws.DockerImages == nil {
		errs = append(errs, fmt.Errorf("%s.docker_images: required for docker stack CVE scanning", label))
	}
	if ws.DockerImages != nil {
		if ws.Stack == StackDocker && len(ws.DockerImages.Files) == 0 {
			errs = append(errs, fmt.Errorf("%s.docker_images.files: required for docker stack CVE scanning", label))
		}
		for _, f := range ws.DockerImages.Files {
			errs = append(errs, validateDockerImageFile(label, ws.Path, f)...)
		}
		for _, image := range ws.DockerImages.RuntimeImages {
			errs = append(errs, validateRuntimeImageReference(label, image)...)
		}
	}

	return errs
}

func validateVerificationProfileWithOptions(label string, ws Workspace, allowScriptDrift bool) []error {
	profile := ws.Verification
	var errs []error
	if profile.Version != VerificationVersion {
		return []error{fmt.Errorf("%s.verification.version: must be %d", label, VerificationVersion)}
	}
	switch profile.State {
	case VerificationScanOnly:
		if len(profile.Steps) != 0 {
			errs = append(errs, fmt.Errorf("%s.verification.steps: must be empty for scan_only", label))
		}
		return errs
	case VerificationReady:
		if len(profile.Steps) == 0 {
			return []error{fmt.Errorf("%s.verification.steps: at least one explicit step is required for ready", label)}
		}
		if len(profile.Steps) > 16 {
			return []error{fmt.Errorf("%s.verification.steps: at most 16 steps are allowed", label)}
		}
	default:
		return []error{fmt.Errorf("%s.verification.state: must be ready or scan_only", label)}
	}

	seenNames := make(map[string]bool, len(profile.Steps))
	for index, step := range profile.Steps {
		stepLabel := fmt.Sprintf("%s.verification.steps[%d]", label, index)
		if !projectNamePattern.MatchString(step.Name) || seenNames[step.Name] {
			errs = append(errs, fmt.Errorf("%s.name: must be a unique verification step name", stepLabel))
		}
		seenNames[step.Name] = true
		if !projectNamePattern.MatchString(step.Service) {
			errs = append(errs, fmt.Errorf("%s.service: must be a Compose service name", stepLabel))
		}
		if err := validateVerificationCommand(step.Command); err != nil {
			errs = append(errs, fmt.Errorf("%s.command: %w", stepLabel, err))
		}
		if len(step.Command) > 0 {
			if _, err := builtInAdapter(ws.Stack, step.Command[0]); err == nil && step.Command[0] != ws.PackageManager {
				errs = append(errs, fmt.Errorf("%s.command: package factory %q does not match workspace package_manager %q", stepLabel, step.Command[0], ws.PackageManager))
			}
		}
		if err := validatePackageVerificationStep(ws.Path, step, allowScriptDrift); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", stepLabel, err))
		}
		if step.TimeoutSeconds <= 0 || step.TimeoutSeconds > int((2*time.Hour)/time.Second) {
			errs = append(errs, fmt.Errorf("%s.timeout_seconds: must be between 1 and 7200", stepLabel))
		}
		if err := validateSuccessExitCodes(step.SuccessExitCodes); err != nil {
			errs = append(errs, fmt.Errorf("%s.success_exit_codes: %w", stepLabel, err))
		}
		if err := validateVerificationComposeFile(ws.Path, step.ComposeFile, step.Service, ws.Platform); err != nil {
			errs = append(errs, fmt.Errorf("%s.compose_file: %w", stepLabel, err))
		}
	}
	return errs
}

func validateVerificationCommand(command []string) error {
	if len(command) == 0 {
		return errors.New("explicit argv is required; inherited service commands are not allowed")
	}
	if len(command) > 128 {
		return errors.New("argv exceeds 128 entries")
	}
	unsafePrograms := map[string]bool{"sh": true, "bash": true, "zsh": true, "fish": true, "cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true}
	unsafeArguments := map[string]bool{"dev": true, "serve": true, "server": true, "start": true, "preview": true, "watch": true, "--watch": true, "-w": true, "--interactive": true, "--tty": true}
	total := 0
	for index, arg := range command {
		total += len(arg)
		if arg == "" || strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("argv[%d] must be a non-empty single-line value", index)
		}
		if len(arg) > 4096 || total > 64<<10 {
			return errors.New("argv exceeds the configured size limit")
		}
		lower := strings.ToLower(arg)
		if index == 0 && unsafePrograms[filepath.Base(lower)] {
			return errors.New("shell executables are not allowed")
		}
		if unsafeArguments[lower] || strings.HasPrefix(lower, "--watch=") {
			return fmt.Errorf("interactive, dev, preview, and watch arguments are not allowed (%s)", lower)
		}
	}
	return nil
}

// ValidateVerificationCommand exposes the same fail-closed argv policy to
// declarative onboarding discovery without executing project code.
func ValidateVerificationCommand(command []string) error {
	return validateVerificationCommand(command)
}

func validatePackageVerificationCommand(root string, command []string) error {
	_, _, err := resolvePackageVerificationScript(root, command)
	return err
}

const verificationScriptHashPrefix = "sha256:"

var verificationScriptHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type resolvedPackageVerificationScript struct {
	Body string
}

func packageVerificationScriptName(command []string) (string, bool, error) {
	if len(command) == 0 {
		return "", false, nil
	}
	script := ""
	registry, err := catalog.New()
	if err != nil {
		return "", false, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	for _, adapter := range registry.Adapters() {
		provider, ok := adapter.(ecosystem.VerificationProvider)
		if !ok {
			continue
		}
		if detected, ok := provider.VerificationScript(command); ok {
			if script != "" {
				return "", false, errors.New("package verification factory is ambiguous")
			}
			script = detected
		}
	}
	if script == "" {
		return "", false, nil
	}
	return script, true, nil
}

func resolvePackageVerificationScript(root string, command []string) (resolvedPackageVerificationScript, bool, error) {
	script, mapped, err := packageVerificationScriptName(command)
	if err != nil || !mapped {
		return resolvedPackageVerificationScript{}, false, err
	}
	path := filepath.Join(root, "package.json")
	info, err := os.Lstat(path)
	if err != nil {
		return resolvedPackageVerificationScript{}, false, errors.New("package.json is required for the selected package verification factory")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return resolvedPackageVerificationScript{}, false, errors.New("package.json must be a non-symlink regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return resolvedPackageVerificationScript{}, false, fmt.Errorf("read package verification metadata: %w", err)
	}
	var document struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return resolvedPackageVerificationScript{}, false, fmt.Errorf("parse package verification metadata: %w", err)
	}
	body, ok := document.Scripts[script]
	if !ok || !safePackageVerificationScript(body) {
		return resolvedPackageVerificationScript{}, false, fmt.Errorf("package script %q is missing or contains shell, dev, preview, watch, or interactive behavior", script)
	}
	return resolvedPackageVerificationScript{Body: body}, true, nil
}

func verificationScriptBodyHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return verificationScriptHashPrefix + fmt.Sprintf("%x", sum)
}

func validatePackageVerificationStep(root string, step VerificationStep, allowScriptDrift bool) error {
	resolved, mapped, err := resolvePackageVerificationScript(root, step.Command)
	if err != nil {
		return fmt.Errorf("command: %w", err)
	}
	if !mapped {
		if step.ScriptBodyHash != "" {
			return errors.New("script_body_hash: only package manifest scripts may have a body hash")
		}
		return nil
	}
	if step.ScriptBodyHash == "" {
		return nil
	}
	if !verificationScriptHashPattern.MatchString(step.ScriptBodyHash) {
		return errors.New("script_body_hash: must use sha256:<64 lowercase hex> format")
	}
	if !allowScriptDrift && step.ScriptBodyHash != verificationScriptBodyHash(resolved.Body) {
		return fmt.Errorf("script_body_hash: approved package script changed for verification step %q; run `vuelta project verify approve --directory PATH --yes` to re-approve it", step.Name)
	}
	return nil
}

// PinVerificationScriptBodies records the exact decoded package.json script
// string for each manifest-backed verification step. JSON formatting outside
// the string is ignored; every byte inside the decoded script is significant.
func PinVerificationScriptBodies(root string, profile VerificationProfile) (VerificationProfile, error) {
	pinned := profile
	pinned.Steps = append([]VerificationStep(nil), profile.Steps...)
	for index := range pinned.Steps {
		resolved, mapped, err := resolvePackageVerificationScript(root, pinned.Steps[index].Command)
		if err != nil {
			return VerificationProfile{}, fmt.Errorf("verification step %q: %w", pinned.Steps[index].Name, err)
		}
		if !mapped {
			pinned.Steps[index].ScriptBodyHash = ""
			continue
		}
		pinned.Steps[index].ScriptBodyHash = verificationScriptBodyHash(resolved.Body)
	}
	return pinned, nil
}

// ValidateVerificationScriptBodies rejects a changed approved package script.
// Legacy steps without a hash and steps not backed by a manifest remain valid.
func ValidateVerificationScriptBodies(root string, profile VerificationProfile) error {
	for _, step := range profile.Steps {
		if err := validatePackageVerificationStep(root, step, false); err != nil {
			return fmt.Errorf("verification step %q: %w", step.Name, err)
		}
	}
	return nil
}

func safePackageVerificationScript(body string) bool {
	if body == "" || strings.ContainsAny(body, "\r\n;&|`$><") {
		return false
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "--watch") || strings.Contains(lower, " -w") {
		return false
	}
	unsafeWord := regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(dev|watch|serve|server|start|preview|interactive)([^a-z0-9_-]|$)`)
	return !unsafeWord.MatchString(body)
}

func validateSuccessExitCodes(codes []int) error {
	if len(codes) == 0 {
		return errors.New("at least one explicit exit code is required")
	}
	seen := make(map[int]bool, len(codes))
	for _, code := range codes {
		if code < 0 || code > 125 || seen[code] {
			return errors.New("codes must be unique values between 0 and 125")
		}
		seen[code] = true
	}
	return nil
}

func validateVerificationComposeFile(root, name, service, workspacePlatform string) error {
	if name == "" || filepath.IsAbs(name) {
		return errors.New("must be a project-relative regular file")
	}
	cleaned := filepath.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("must stay inside the workspace")
	}
	path := filepath.Join(root, cleaned)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot inspect selected Compose file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a non-symlink regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read selected Compose file: %w", err)
	}
	var document struct {
		Services map[string]struct {
			Platform string `yaml:"platform"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("cannot parse selected Compose file: %w", err)
	}
	selected, ok := document.Services[service]
	if !ok {
		return fmt.Errorf("service %q does not exist", service)
	}
	if selected.Platform != "" && selected.Platform != "linux/amd64" && selected.Platform != "linux/arm64" {
		return errors.New("service platform must be linux/amd64 or linux/arm64")
	}
	if selected.Platform != "" && workspacePlatform != "" && selected.Platform != workspacePlatform {
		return fmt.Errorf("service platform %q does not match workspace platform %q", selected.Platform, workspacePlatform)
	}
	return nil
}

func canonicalWorkspacePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func builtInAdapter(stack, packageManager string) (ecosystem.Adapter, error) {
	registry, err := catalog.New()
	if err != nil {
		return nil, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	return registry.Lookup(stack, packageManager)
}

// validateRuntimeImageReference accepts either an exact digest pin or a bare
// tag/name reference recorded as intent for scan-time resolution. A reference
// that attempts a digest pin but does not match the exact digest grammar
// still fails hard: a malformed pin must never be silently downgraded to
// intent.
func validateRuntimeImageReference(label, image string) []error {
	if image == "" {
		return []error{fmt.Errorf("%s.docker_images.runtime_images: empty image reference", label)}
	}
	if strings.Contains(image, "@") {
		if !digestRefPattern.MatchString(image) {
			return []error{fmt.Errorf("%s.docker_images.runtime_images: %q is not pinned to a valid digest", label, image)}
		}
	}
	if strings.ContainsAny(image, " \t\r\n") {
		return []error{fmt.Errorf("%s.docker_images.runtime_images: %q is not a valid image reference", label, image)}
	}
	return nil
}

// validateDockerImageFile ensures f stays inside root as a project-relative
// regular file: no absolute paths, no "..", no symlinks.
func validateDockerImageFile(label, root, f string) []error {
	var errs []error

	if filepath.IsAbs(f) {
		errs = append(errs, fmt.Errorf("%s.docker_images.files: %q must be project-relative, not absolute", label, f))
		return errs
	}

	cleaned := filepath.Clean(f)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		errs = append(errs, fmt.Errorf("%s.docker_images.files: %q escapes the project directory", label, f))
		return errs
	}

	full := filepath.Join(root, cleaned)
	lstat, err := os.Lstat(full)
	if err != nil {
		errs = append(errs, fmt.Errorf("%s.docker_images.files: %s: %w", label, f, err))
		return errs
	}
	if lstat.Mode()&os.ModeSymlink != 0 {
		errs = append(errs, fmt.Errorf("%s.docker_images.files: %s is a symlink, not allowed", label, f))
		return errs
	}
	if !lstat.Mode().IsRegular() {
		errs = append(errs, fmt.Errorf("%s.docker_images.files: %s is not a regular file", label, f))
	}

	return errs
}
