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

	"gopkg.in/yaml.v3"
)

// digestRefPattern matches an image reference pinned to a real sha256 digest,
// e.g. "python:3.12-slim@sha256:<64 hex chars>". It rejects unfilled
// placeholders like "@sha256:<digest>".
var digestRefPattern = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
var projectNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Config mirrors the config.yaml schema.
type Config struct {
	Notify           NotifyConfig            `yaml:"notify"`
	VulnScan         VulnScanConfig          `yaml:"vuln_scan"`
	GithubAdvisories GithubAdvisoriesConfig  `yaml:"github_advisories"`
	Update           UpdateConfig            `yaml:"update"`
	Autofix          AutofixConfig           `yaml:"autofix"`
	DeployTask       DeployTaskConfig        `yaml:"deploy_task"`
	ProductionWorker *ProductionWorkerConfig `yaml:"production_worker,omitempty"`
	Workspaces       []Workspace             `yaml:"workspaces"`
	Git              GitConfig               `yaml:"git"`

	sourcePath string
	sourceMode os.FileMode
}

type NotifyConfig struct {
	WebhookURL string         `yaml:"webhook_url"`
	Telegram   TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
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

type UpdateConfig struct {
	MinReleaseAgeDays int               `yaml:"min_release_age_days"`
	SnapshotTTLHours  int               `yaml:"snapshot_ttl_hours"`
	SnapshotStateDir  string            `yaml:"snapshot_state_dir"`
	Egress            EgressConfig      `yaml:"egress"`
	Images            map[string]string `yaml:"images"`
	Tools             map[string]string `yaml:"tools"`
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
	StateDir               string              `yaml:"state_dir"`
	SourceMode             string              `yaml:"source_mode"`
	QueueFile              string              `yaml:"queue_file"`
	ManifestDir            string              `yaml:"manifest_dir"`
	CandidatePublicKey     string              `yaml:"candidate_public_key"`
	GitMirror              string              `yaml:"git_mirror"`
	GitRemote              string              `yaml:"git_remote"`
	GitExpectedOrigin      string              `yaml:"git_expected_origin"`
	GitTagPrefix           string              `yaml:"git_tag_prefix"`
	GitTrustedFingerprint  string              `yaml:"git_trusted_fingerprint"`
	ManifestPublicKey      string              `yaml:"manifest_public_key"`
	MaxCandidateAgeMinutes int                 `yaml:"max_candidate_age_minutes"`
	OperationTimeoutSecond int                 `yaml:"operation_timeout_seconds"`
	Projects               []ProductionProject `yaml:"projects"`
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

// TestProfile is a structured, allowlisted test command — never a raw shell string.
type TestProfile struct {
	ComposeFile string   `yaml:"compose_file"`
	Service     string   `yaml:"service"`
	RunArgs     []string `yaml:"run_args"`
	// TimeoutMinutes bounds the test run (part B §7 step 6); 0 means the
	// pipeline's default of 15 minutes.
	TimeoutMinutes int `yaml:"timeout_minutes,omitempty"`
}

// DockerImagesSpec restricts docker-stack analysis to explicit project-relative files.
type DockerImagesSpec struct {
	Files         []string `yaml:"files"`
	RuntimeImages []string `yaml:"runtime_images"`
	Platforms     []string `yaml:"platforms"`
}

type Workspace struct {
	Name           string      `yaml:"name,omitempty"`
	Path           string      `yaml:"path"`
	Stack          string      `yaml:"stack"`
	PackageManager string      `yaml:"package_manager"`
	Test           TestProfile `yaml:"test"`
	Branch         string      `yaml:"branch"`
	Remote         string      `yaml:"remote"`
	// AllowedChangedPaths overrides the legacy config-wide Git allowlist for
	// this workspace. Older configs continue to use git.allowed_changed_paths.
	AllowedChangedPaths []string          `yaml:"allowed_changed_paths,omitempty"`
	DockerImages        *DockerImagesSpec `yaml:"docker_images,omitempty"`
}

type GitConfig struct {
	PushMode            string   `yaml:"push_mode"`
	AllowedChangedPaths []string `yaml:"allowed_changed_paths"`
}

// LocalPackagePolicy is the deliberately narrow configuration for
// `vuelta package local`. It is loaded from its own file rather than the
// sandboxed-pipeline configuration, so a local project need not have Git or
// Docker available. It never accepts commands, registries, proxies, or
// credentials.
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config %s: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.sourcePath = path
	cfg.sourceMode = info.Mode()
	return cfg, nil
}

// Parse decodes config bytes with the same safe defaults and strict field
// checking as Load, without reading from the filesystem.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown keys, e.g. an arbitrary shell "cmd" smuggled into a test profile

	// Security-sensitive autofix defaults are safe even when an older config
	// omits the whole block: it stays disabled and, if later enabled, grants no
	// shell tool. Explicit YAML values still override these defaults and are
	// validated below.
	cfg := Config{Autofix: AutofixConfig{
		ClaudeBin:    "claude",
		MaxTurns:     10,
		AllowedTools: "Read,Edit,Grep",
	}, Update: UpdateConfig{SnapshotTTLHours: 24}}
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// PermissionWarning reports a non-fatal warning when the config file is not
// restricted to owner read/write (0600).
func (c *Config) PermissionWarning() (string, bool) {
	if c.sourceMode.Perm() != 0o600 {
		return fmt.Sprintf("warning: %s has permissions %04o, expected 0600", c.sourcePath, c.sourceMode.Perm()), true
	}
	return "", false
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

	seenNames := make(map[string]int, len(c.Workspaces))
	seenPaths := make(map[string]int, len(c.Workspaces))
	for i, ws := range c.Workspaces {
		errs = append(errs, validateWorkspace(i, ws)...)
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

	for name, ref := range c.Update.Images {
		if !digestRefPattern.MatchString(ref) {
			errs = append(errs, fmt.Errorf("update.images[%s]: %q is not pinned to a digest (expected an ...@sha256:<64 hex chars> reference)", name, ref))
		}
	}

	errs = append(errs, validateEgress(c.Update.Egress)...)
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
	errs = append(errs, validateDeployTask(c.DeployTask)...)
	errs = append(errs, validateProductionWorker(c.ProductionWorker)...)
	if c.Git.PushMode != "" && c.Git.PushMode != "review_branch" && c.Git.PushMode != "direct_branch" {
		errs = append(errs, fmt.Errorf("git.push_mode: %q is not supported (review_branch|direct_branch)", c.Git.PushMode))
	}

	return errors.Join(errs...)
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
		AllowedChangedPaths []string
	}{ws, c.Update.MinReleaseAgeDays, c.Update.Egress, c.Update.Images, c.Update.Tools, c.AllowedChangedPaths(ws)}
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

	if ws.Test.ComposeFile == "" {
		errs = append(errs, fmt.Errorf("%s.test.compose_file: required", label))
	}
	if ws.Test.Service == "" {
		errs = append(errs, fmt.Errorf("%s.test.service: required", label))
	} else if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(ws.Test.Service) {
		errs = append(errs, fmt.Errorf("%s.test.service: must be a compose service name", label))
	}
	for _, arg := range ws.Test.RunArgs {
		if arg != "--rm" && arg != "--no-TTY" {
			errs = append(errs, fmt.Errorf("%s.test.run_args: %q is not allowlisted", label, arg))
		}
	}

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
