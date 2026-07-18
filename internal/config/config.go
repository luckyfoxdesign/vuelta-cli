// Package config loads and validates vuelta's config.yaml (~/.config/vuelta/config.yaml).
//
// Validation never walks parent directories or discovers projects: only the
// paths explicitly listed under workspaces[] are ever scanned or updated.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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

// Config mirrors the config.yaml schema.
type Config struct {
	Docker           *DockerConfig           `yaml:"docker,omitempty"`
	Notify           NotifyConfig            `yaml:"notify"`
	VulnScan         VulnScanConfig          `yaml:"vuln_scan"`
	GithubAdvisories GithubAdvisoriesConfig  `yaml:"github_advisories"`
	Update           UpdateConfig            `yaml:"update"`
	Autofix          AutofixConfig           `yaml:"autofix"`
	DeployTask       DeployTaskConfig        `yaml:"deploy_task"`
	ProductionWorker *ProductionWorkerConfig `yaml:"production_worker,omitempty"`
	Workspaces       []Workspace             `yaml:"workspaces"`
	Git              GitConfig               `yaml:"git"`
}

// DockerConfig holds the developer-side daemon authority used by scan and
// update. The production deploy worker has a separate endpoint below so the
// two trust domains cannot be selected by the same inherited context.
type DockerConfig struct {
	Developer *DockerEndpointConfig `yaml:"developer,omitempty"`
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
	ID                      string   `yaml:"id"`
	ServerVersion           string   `yaml:"server_version"`
	OperatingSystem         string   `yaml:"operating_system"`
	Architecture            string   `yaml:"architecture"`
	MinimumAPIVersion       string   `yaml:"minimum_api_version"`
	RequiredSecurityOptions []string `yaml:"required_security_options"`
}

type NotifyConfig struct {
	WebhookURLEnv string         `yaml:"webhook_url_env"`
	Telegram      TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	BotTokenEnv string `yaml:"bot_token_env"`
	ChatID      string `yaml:"chat_id"`
}

const (
	// NotifyWebhookURLEnv is the only environment variable that may supply a
	// webhook credential. Keeping the name fixed prevents a config file from
	// routing an unrelated process secret into a notification request.
	NotifyWebhookURLEnv = "VUELTA_NOTIFY_WEBHOOK_URL"
	// NotifyTelegramBotTokenEnv is the only environment variable that may
	// supply a Telegram bot credential.
	NotifyTelegramBotTokenEnv = "VUELTA_NOTIFY_TELEGRAM_BOT_TOKEN"
)

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
	SnapshotStateDir  string             `yaml:"snapshot_state_dir"`
	Egress            EgressConfig       `yaml:"egress"`
	Images            map[string]string  `yaml:"images"`
	Tools             map[string]string  `yaml:"tools"`
	ToolchainProfiles []ToolchainProfile `yaml:"toolchain_profiles,omitempty"`
}

const ToolchainProfileVersion = 1

// ToolchainProfile is one immutable, curated package-manager environment.
// Commands are compiled into Vuelta; profiles can select versions and
// capabilities but cannot introduce arbitrary argv or shell fragments.
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
}

type AutofixConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ContainerImage string `yaml:"container_image"`
	ClaudeBin      string `yaml:"claude_bin"`
	MaxTurns       int    `yaml:"max_turns"`
	AllowedTools   string `yaml:"allowed_tools"`
}

type DeployTaskConfig struct {
	Mode      string `yaml:"mode"`
	TagPrefix string `yaml:"tag_prefix"`
	QueueFile string `yaml:"queue_file"`
}

// ProductionWorkerConfig configures the server-only deploy worker. Its public
// keys authenticate delivery and manifests; private signing keys are never
// read by vuelta or stored in this file.
type ProductionWorkerConfig struct {
	Docker                 *DockerEndpointConfig `yaml:"docker,omitempty"`
	StateDir               string                `yaml:"state_dir"`
	SourceMode             string                `yaml:"source_mode"`
	QueueFile              string                `yaml:"queue_file"`
	ManifestDir            string                `yaml:"manifest_dir"`
	CandidatePublicKey     string                `yaml:"candidate_public_key"`
	GitMirror              string                `yaml:"git_mirror"`
	GitRemote              string                `yaml:"git_remote"`
	GitExpectedOrigin      string                `yaml:"git_expected_origin"`
	GitTagPrefix           string                `yaml:"git_tag_prefix"`
	GitTrustedFingerprint  string                `yaml:"git_trusted_fingerprint"`
	ManifestPublicKey      string                `yaml:"manifest_public_key"`
	MaxCandidateAgeMinutes int                   `yaml:"max_candidate_age_minutes"`
	OperationTimeoutSecond int                   `yaml:"operation_timeout_seconds"`
	Projects               []ProductionProject   `yaml:"projects"`
}

// ProductionProject is a fixed per-project Compose adapter. There are no
// migration commands or arbitrary shell snippets in the production schema.
type ProductionProject struct {
	Name            string `yaml:"name"`
	ImageRepository string `yaml:"image_repository"`
	ComposeFile     string `yaml:"compose_file"`
	Service         string `yaml:"service"`
	HealthURL       string `yaml:"health_url"`
	SmokeURL        string `yaml:"smoke_url"`
}

const (
	VerificationVersion  = 1
	VerificationReady    = "ready"
	VerificationScanOnly = "scan_only"
)

// VerificationProfile is the versioned, explicit update gate for one
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

// packageManagersByStack lists the package managers valid for each stack.
// The docker stack has no package manager of its own.
var packageManagersByStack = map[string]map[string]bool{
	StackPython: {"poetry": true, "uv": true, "pip-tools": true},
	StackNode:   {"npm": true, "pnpm": true, "bun": true},
	StackDocker: {},
}

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

// Parse decodes config bytes with the same safe defaults and strict field
// checking as Load, without reading from the filesystem.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown keys, e.g. an arbitrary shell "cmd" smuggled into a verification profile

	// Security-sensitive autofix defaults are safe even when an older config
	// omits the whole block: it stays disabled and, if later enabled, grants no
	// shell tool. Explicit YAML values still override these defaults and are
	// validated below.
	cfg := Config{Autofix: AutofixConfig{
		ClaudeBin:    "claude",
		MaxTurns:     10,
		AllowedTools: "Read,Edit,Grep",
	}, Update: UpdateConfig{MinReleaseAgeDays: 7, SnapshotTTLHours: 24}}
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
		if ws.Verification.State == VerificationScanOnly {
			warnings = append(warnings, fmt.Sprintf("project %q is scan-only; configure verification.steps before running update or update --dry-run", WorkspaceName(ws)))
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
// every workspace path must exist and be a git repository, stack/package_manager
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
		errs = append(errs, validateDockerEndpoint("docker.developer", c.Docker.Developer, false)...)
	}
	if c.Update.MinReleaseAgeDays < 0 {
		errs = append(errs, errors.New("update.min_release_age_days: must not be negative"))
	}
	if c.Update.SnapshotTTLHours != 0 && (c.Update.SnapshotTTLHours < 1 || c.Update.SnapshotTTLHours > 168) {
		errs = append(errs, errors.New("update.snapshot_ttl_hours: must be between 1 and 168"))
	}
	if c.Update.SnapshotStateDir != "" && !filepath.IsAbs(c.Update.SnapshotStateDir) {
		errs = append(errs, errors.New("update.snapshot_state_dir: must be absolute when set"))
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
	errs = append(errs, validateNotifyConfig(c.Notify)...)
	errs = append(errs, validateDeployTask(c.DeployTask)...)
	errs = append(errs, validateProductionWorker(c.ProductionWorker)...)
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
	managers, ok := packageManagersByStack[profile.Stack]
	if !ok || profile.Stack == StackDocker || !managers[profile.PackageManager] {
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
	} else if expected := map[string]string{"npm": "ncu", "pnpm": "pnpm", "bun": "ncu", "poetry": "poetry", "uv": "uv", "pip-tools": "pip"}[profile.PackageManager]; expected != "" && profile.Scanner != expected {
		errs = append(errs, fmt.Errorf("%s.scanner: must be %q for package manager %q", label, expected, profile.PackageManager))
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
	allowedLocks := map[string]map[string]bool{
		"npm": {"npm-v2": true, "npm-v3": true}, "pnpm": {"pnpm-v6": true, "pnpm-v9": true},
		"bun": {"bun-text": true}, "poetry": {"poetry-v2": true}, "uv": {"uv-v1": true},
		"pip-tools": {"requirements": true},
	}[profile.PackageManager]
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

func validateNotifyConfig(c NotifyConfig) []error {
	var errs []error
	if c.WebhookURLEnv != "" && c.WebhookURLEnv != NotifyWebhookURLEnv {
		errs = append(errs, fmt.Errorf("notify.webhook_url_env: must be %q when configured", NotifyWebhookURLEnv))
	}
	if c.Telegram.BotTokenEnv != "" && c.Telegram.BotTokenEnv != NotifyTelegramBotTokenEnv {
		errs = append(errs, fmt.Errorf("notify.telegram.bot_token_env: must be %q when configured", NotifyTelegramBotTokenEnv))
	}
	if (c.Telegram.BotTokenEnv == "") != (c.Telegram.ChatID == "") {
		errs = append(errs, errors.New("notify.telegram: bot_token_env and chat_id must be configured together"))
	}
	return errs
}

// SnapshotTTL returns the validated lifetime of a package update plan.
func (c Config) SnapshotTTL() time.Duration {
	if c.Update.SnapshotTTLHours == 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.Update.SnapshotTTLHours) * time.Hour
}

// SnapshotStateDir returns the private local state directory used for package
// update plans. An explicit config value is preferred; the default is scoped
// to the user's OS configuration directory.
func (c Config) SnapshotStateDir() (string, error) {
	if c.Update.SnapshotStateDir != "" {
		return c.Update.SnapshotStateDir, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(dir, "vuelta", "update-snapshots"), nil
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
	}
	return errs
}

func validateProductionWorker(c *ProductionWorkerConfig) []error {
	if c == nil {
		return nil
	}
	var errs []error
	errs = append(errs, validateDockerEndpoint("production_worker.docker", c.Docker, true)...)
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.ManifestDir) {
		errs = append(errs, errors.New("production_worker state_dir and manifest_dir must be absolute paths"))
	}
	if c.MaxCandidateAgeMinutes <= 0 || c.OperationTimeoutSecond <= 0 {
		errs = append(errs, errors.New("production_worker max_candidate_age_minutes and operation_timeout_seconds must be positive"))
	}
	for field, encoded := range map[string]string{"manifest_public_key": c.ManifestPublicKey} {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != 32 {
			errs = append(errs, fmt.Errorf("production_worker.%s must be a base64 Ed25519 public key", field))
		}
	}
	switch c.SourceMode {
	case "signed_queue_file":
		if !filepath.IsAbs(c.QueueFile) {
			errs = append(errs, errors.New("production_worker.queue_file must be an absolute path for signed_queue_file"))
		}
		decoded, err := base64.StdEncoding.DecodeString(c.CandidatePublicKey)
		if err != nil || len(decoded) != 32 {
			errs = append(errs, errors.New("production_worker.candidate_public_key must be a base64 Ed25519 public key for signed_queue_file"))
		}
	case "git_tag":
		if !filepath.IsAbs(c.GitMirror) || c.GitRemote == "" || c.GitExpectedOrigin == "" || c.GitTagPrefix == "" || !regexp.MustCompile(`^[A-Fa-f0-9]{40,64}$`).MatchString(c.GitTrustedFingerprint) {
			errs = append(errs, errors.New("production_worker git_tag requires absolute git_mirror, remote, expected_origin, tag_prefix, and an allowlisted signing fingerprint"))
		}
	default:
		errs = append(errs, errors.New("production_worker.source_mode must be signed_queue_file or git_tag"))
	}
	if len(c.Projects) == 0 {
		errs = append(errs, errors.New("production_worker.projects: at least one project is required"))
	}
	seen := make(map[string]bool)
	for i, project := range c.Projects {
		label := fmt.Sprintf("production_worker.projects[%d]", i)
		if !projectNamePattern.MatchString(project.Name) || seen[project.Name] {
			errs = append(errs, fmt.Errorf("%s.name must be a unique project name", label))
		}
		seen[project.Name] = true
		if !validImageRepository(project.ImageRepository) {
			errs = append(errs, fmt.Errorf("%s.image_repository must be an allowlisted repository without a tag or digest", label))
		}
		if !filepath.IsAbs(project.ComposeFile) || !projectNamePattern.MatchString(project.Service) {
			errs = append(errs, fmt.Errorf("%s.compose_file must be absolute and service must be a compose service name", label))
		}
		for name, rawURL := range map[string]string{"health_url": project.HealthURL, "smoke_url": project.SmokeURL} {
			u, err := url.Parse(rawURL)
			if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
				errs = append(errs, fmt.Errorf("%s.%s must be HTTPS or loopback HTTP", label, name))
			}
		}
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

func validImageRepository(repository string) bool {
	if repository == "" || strings.Contains(repository, "@") || strings.ContainsAny(repository, " \t\n") {
		return false
	}
	lastSlash := strings.LastIndexByte(repository, '/')
	return !strings.Contains(repository[lastSlash+1:], ":")
}

func validateDeployTask(c DeployTaskConfig) []error {
	var errs []error
	switch c.Mode {
	case "git_tag":
		if c.TagPrefix == "" {
			errs = append(errs, errors.New("deploy_task.tag_prefix: required for git_tag"))
		}
	case "queue_file":
		if c.QueueFile == "" {
			errs = append(errs, errors.New("deploy_task.queue_file: required for queue_file"))
		}
	case "":
		errs = append(errs, errors.New("deploy_task.mode: required (git_tag|queue_file)"))
	default:
		errs = append(errs, fmt.Errorf("deploy_task.mode: %q is not supported (git_tag|queue_file)", c.Mode))
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
	if c.Autofix.Enabled {
		if !digestRefPattern.MatchString(c.Autofix.ContainerImage) {
			errs = append(errs, errors.New("autofix.container_image: must be an immutable sha256 digest when autofix is enabled"))
		}
		if c.Autofix.MaxTurns <= 0 {
			errs = append(errs, errors.New("autofix.max_turns: must be positive when autofix is enabled"))
		}
		if !allowedAutofixTools(c.Autofix.AllowedTools) {
			errs = append(errs, errors.New("autofix.allowed_tools: must be a non-empty subset of Read,Edit,Grep; Bash is prohibited"))
		}
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

func allowedAutofixTools(value string) bool {
	allowed := map[string]bool{"Read": true, "Edit": true, "Grep": true}
	seen := make(map[string]bool)
	for _, tool := range strings.Split(value, ",") {
		tool = strings.TrimSpace(tool)
		if !allowed[tool] || seen[tool] {
			return false
		}
		seen[tool] = true
	}
	return len(seen) > 0
}

func validateWorkspace(i int, ws Workspace) []error {
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

	if _, err := os.Stat(filepath.Join(ws.Path, ".git")); err != nil {
		errs = append(errs, fmt.Errorf("%s.path %s: not a git repository", label, ws.Path))
	}

	managers, ok := packageManagersByStack[ws.Stack]
	if !ok {
		errs = append(errs, fmt.Errorf("%s.stack: %q is not a supported stack (python|node|docker)", label, ws.Stack))
	} else if ws.Stack == StackDocker {
		if ws.PackageManager != "" {
			errs = append(errs, fmt.Errorf("%s.package_manager: docker stack has no package manager", label))
		}
	} else if !managers[ws.PackageManager] {
		errs = append(errs, fmt.Errorf("%s.package_manager: %q is not valid for stack %q", label, ws.PackageManager, ws.Stack))
	}

	errs = append(errs, validateVerificationProfile(label, ws)...)

	if ws.Stack == StackDocker && ws.DockerImages == nil {
		errs = append(errs, fmt.Errorf("%s.docker_images: required for docker stack CVE scanning", label))
	}
	if ws.DockerImages != nil {
		if ws.Stack == StackDocker && len(ws.DockerImages.Files) == 0 {
			errs = append(errs, fmt.Errorf("%s.docker_images.files: required for docker stack CVE scanning", label))
		}
		if ws.Stack == StackDocker && len(ws.DockerImages.RuntimeImages) == 0 {
			errs = append(errs, fmt.Errorf("%s.docker_images.runtime_images: required to scan the immutable production runtime image", label))
		}
		for _, f := range ws.DockerImages.Files {
			errs = append(errs, validateDockerImageFile(label, ws.Path, f)...)
		}
		for _, image := range ws.DockerImages.RuntimeImages {
			if !digestRefPattern.MatchString(image) {
				errs = append(errs, fmt.Errorf("%s.docker_images.runtime_images: %q is not pinned to a digest", label, image))
			}
		}
	}

	return errs
}

func validateVerificationProfile(label string, ws Workspace) []error {
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
		if ws.Stack == StackNode && len(step.Command) > 0 && (step.Command[0] == "npm" || step.Command[0] == "pnpm" || step.Command[0] == "bun") && step.Command[0] != ws.PackageManager {
			errs = append(errs, fmt.Errorf("%s.command: package factory %q does not match workspace package_manager %q", stepLabel, step.Command[0], ws.PackageManager))
		}
		if err := validatePackageVerificationCommand(ws.Path, step.Command); err != nil {
			errs = append(errs, fmt.Errorf("%s.command: %w", stepLabel, err))
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
	if len(command) == 0 || (command[0] != "npm" && command[0] != "pnpm" && command[0] != "bun") {
		return nil
	}
	script := ""
	if command[0] == "npm" && len(command) >= 2 && command[1] == "test" {
		script = "test"
	} else if len(command) >= 3 && command[1] == "run" {
		script = command[2]
	}
	if script == "" {
		return nil
	}
	path := filepath.Join(root, "package.json")
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("package.json is required for the selected package verification factory")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("package.json must be a non-symlink regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read package verification metadata: %w", err)
	}
	var document struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse package verification metadata: %w", err)
	}
	body, ok := document.Scripts[script]
	if !ok || !safePackageVerificationScript(body) {
		return fmt.Errorf("package script %q is missing or contains shell, dev, preview, watch, or interactive behavior", script)
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
