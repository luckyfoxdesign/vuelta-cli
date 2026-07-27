package corpus

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ManifestSchemaVersion = 1
	maxManifestBytes      = 1 << 20
)

var (
	slugPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$`)
	githubPartPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$`)
	fullCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

var allowedManagers = []string{"npm", "pnpm", "poetry", "uv", "pip-tools", "requirements", "bun"}
var allowedLicenses = []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}

// Manifest is the strict, versioned stable or candidate corpus definition.
type Manifest struct {
	SchemaVersion int    `yaml:"schema_version" json:"schema_version"`
	Cases         []Case `yaml:"cases" json:"cases"`
}

// Case describes one immutable public GitHub source and its scan contract.
type Case struct {
	Name                   string     `yaml:"name" json:"name"`
	URL                    string     `yaml:"url" json:"url"`
	Commit                 string     `yaml:"commit" json:"commit"`
	Subdir                 string     `yaml:"subdir" json:"subdir"`
	ExpectedStack          string     `yaml:"expected_stack" json:"expected_stack"`
	ExpectedPackageManager string     `yaml:"expected_package_manager" json:"expected_package_manager"`
	ExpectedLockFormat     string     `yaml:"expected_lock_format" json:"expected_lock_format"`
	License                string     `yaml:"license" json:"license"`
	Features               []string   `yaml:"features" json:"features"`
	Scenarios              []Scenario `yaml:"scenarios" json:"scenarios"`
}

// Scenario is one ordered invocation. Repeat defaults to two for a normal
// onboarding/repeat scenario and may be set to one for an explicit sequence.
type Scenario struct {
	Name   string      `yaml:"name" json:"name"`
	Args   []string    `yaml:"args" json:"args"`
	Repeat int         `yaml:"repeat,omitempty" json:"repeat,omitempty"`
	Expect Expectation `yaml:"expect,omitempty" json:"expect,omitempty"`
}

// Expectation narrows an otherwise failing result into an exact capability or
// fail-open contract. It is intentionally not a known-failure mechanism.
type Expectation struct {
	AllowedStatuses []string             `yaml:"allowed_statuses,omitempty" json:"allowed_statuses,omitempty"`
	AllowedExits    []int                `yaml:"allowed_exit_codes,omitempty" json:"allowed_exit_codes,omitempty"`
	AllowPartial    bool                 `yaml:"allow_partial,omitempty" json:"allow_partial,omitempty"`
	Capabilities    []ExpectedCapability `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

// ExpectedCapability is an exact structured capability assertion. Reason
// matching is bounded to a stable substring because human wording may include
// version identities.
type ExpectedCapability struct {
	Name           string `yaml:"name" json:"name"`
	Status         string `yaml:"status" json:"status"`
	ReasonContains string `yaml:"reason_contains,omitempty" json:"reason_contains,omitempty"`
}

// LoadManifest reads a regular, non-symlink manifest under a fixed size bound.
func LoadManifest(filename string, allowMissingCommit bool) (Manifest, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect corpus manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, errors.New("corpus manifest must be a regular non-symlink file")
	}
	if info.Size() > maxManifestBytes {
		return Manifest{}, fmt.Errorf("corpus manifest exceeds %d bytes", maxManifestBytes)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return Manifest{}, fmt.Errorf("read corpus manifest: %w", err)
	}
	return ParseManifest(data, allowMissingCommit)
}

// ParseManifest strictly decodes one YAML document and validates every field.
func ParseManifest(data []byte, allowMissingCommit bool) (Manifest, error) {
	if len(data) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("corpus manifest exceeds %d bytes", maxManifestBytes)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return Manifest{}, fmt.Errorf("parse corpus manifest: %w", err)
	}
	if err := validateYAMLNode(&node); err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse corpus manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, errors.New("corpus manifest must contain one YAML document")
		}
		return Manifest{}, fmt.Errorf("parse corpus manifest trailer: %w", err)
	}
	if err := manifest.Validate(allowMissingCommit); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func validateYAMLNode(node *yaml.Node) error {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return errors.New("corpus manifest cannot use YAML anchors or aliases")
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks schema, uniqueness, source safety, and scenario contracts.
func (m Manifest) Validate(allowMissingCommit bool) error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("corpus manifest schema_version %d is unsupported (supported: %d)", m.SchemaVersion, ManifestSchemaVersion)
	}
	if len(m.Cases) == 0 {
		return errors.New("corpus manifest must contain at least one case")
	}
	names := make(map[string]bool, len(m.Cases))
	for i, corpusCase := range m.Cases {
		if err := corpusCase.validate(allowMissingCommit); err != nil {
			return fmt.Errorf("validate corpus case %d: %w", i+1, err)
		}
		if names[corpusCase.Name] {
			return fmt.Errorf("corpus case name %q is duplicated", corpusCase.Name)
		}
		names[corpusCase.Name] = true
	}
	return nil
}

func (c Case) validate(allowMissingCommit bool) error {
	if !slugPattern.MatchString(c.Name) {
		return errors.New("name must be a lowercase path-safe slug")
	}
	if err := ValidateGitHubURL(c.URL); err != nil {
		return fmt.Errorf("url: %w", err)
	}
	if c.Commit == "" && !allowMissingCommit {
		return errors.New("stable case commit must be a full 40-character SHA")
	}
	if c.Commit != "" && !fullCommitPattern.MatchString(c.Commit) {
		return errors.New("commit must be a full lowercase 40-character SHA")
	}
	if err := validateSubdir(c.Subdir); err != nil {
		return err
	}
	if c.ExpectedStack != "node" && c.ExpectedStack != "python" {
		return errors.New("expected_stack must be node or python")
	}
	if !slices.Contains(allowedManagers, c.ExpectedPackageManager) {
		return fmt.Errorf("expected_package_manager %q is unsupported", c.ExpectedPackageManager)
	}
	if c.ExpectedPackageManager == "bun" && c.ExpectedStack != "node" {
		return errors.New("bun cases must use expected_stack node")
	}
	if slices.Contains([]string{"poetry", "uv", "pip-tools", "requirements"}, c.ExpectedPackageManager) && c.ExpectedStack != "python" {
		return fmt.Errorf("%s cases must use expected_stack python", c.ExpectedPackageManager)
	}
	if slices.Contains([]string{"npm", "pnpm"}, c.ExpectedPackageManager) && c.ExpectedStack != "node" {
		return fmt.Errorf("%s cases must use expected_stack node", c.ExpectedPackageManager)
	}
	if c.ExpectedLockFormat == "" || len(c.ExpectedLockFormat) > 64 || strings.ContainsAny(c.ExpectedLockFormat, "\x00\r\n") {
		return errors.New("expected_lock_format must be a short non-empty value")
	}
	if !slices.Contains(allowedLicenses, c.License) {
		return fmt.Errorf("license %q is not allowed", c.License)
	}
	if len(c.Features) == 0 {
		return errors.New("features must not be empty")
	}
	seenFeatures := make(map[string]bool, len(c.Features))
	for _, feature := range c.Features {
		if !slugPattern.MatchString(feature) {
			return fmt.Errorf("feature %q must be a lowercase path-safe slug", feature)
		}
		if seenFeatures[feature] {
			return fmt.Errorf("feature %q is duplicated", feature)
		}
		seenFeatures[feature] = true
	}
	if len(c.Scenarios) == 0 {
		return errors.New("scenarios must not be empty")
	}
	seenScenarios := make(map[string]bool, len(c.Scenarios))
	for i, scenario := range c.Scenarios {
		if err := scenario.validate(); err != nil {
			return fmt.Errorf("scenario %d: %w", i+1, err)
		}
		if seenScenarios[scenario.Name] {
			return fmt.Errorf("scenario name %q is duplicated", scenario.Name)
		}
		seenScenarios[scenario.Name] = true
	}
	return nil
}

// ValidateStableCoverage enforces the reviewed 20-case distribution and the
// cross-corpus feature obligations from the acceptance contract.
func (m Manifest) ValidateStableCoverage() error {
	if len(m.Cases) != 20 {
		return fmt.Errorf("stable corpus must contain exactly 20 cases, got %d", len(m.Cases))
	}
	wantManagers := map[string]int{
		"npm": 3, "pnpm": 3, "poetry": 3, "uv": 3,
		"pip-tools": 3, "requirements": 3, "bun": 2,
	}
	gotManagers := make(map[string]int, len(wantManagers))
	features := make(map[string]bool)
	featureCounts := make(map[string]int)
	for _, corpusCase := range m.Cases {
		if slices.Contains(corpusCase.Features, "discovery") {
			return fmt.Errorf("stable corpus case %q cannot use the discovery feature", corpusCase.Name)
		}
		gotManagers[corpusCase.ExpectedPackageManager]++
		for _, feature := range corpusCase.Features {
			features[feature] = true
			featureCounts[feature]++
		}
		if corpusCase.ExpectedPackageManager == "bun" {
			if !slices.Contains(corpusCase.Features, "bun-capability") ||
				!hasExpectedCapabilityContract(corpusCase, 6, "package_updates", "unavailable", "scanner") {
				return fmt.Errorf("stable Bun case %q must define the exact scanner capability contract", corpusCase.Name)
			}
		}
	}
	for manager, want := range wantManagers {
		if gotManagers[manager] != want {
			return fmt.Errorf("stable corpus manager %s must have %d cases, got %d", manager, want, gotManagers[manager])
		}
	}
	requiredFeatures := []string{
		"monorepo-or-workspaces",
		"nested-root",
		"dockerfile",
		"lockfile-schema-variation",
		"dev-or-optional-dependencies",
		"prerelease-or-nonstandard-constraints",
		"requirements-include-directive",
		"requirements-constraint-directive",
		"requirements-hashes",
		"requirements-url-dependency",
		"manifest-without-lockfile",
		"large-project",
		"multi-stack-node",
		"multi-stack-python",
	}
	for _, feature := range requiredFeatures {
		if !features[feature] {
			return fmt.Errorf("stable corpus does not cover required feature %q", feature)
		}
	}
	for _, feature := range []string{"multi-stack-node", "multi-stack-python"} {
		if featureCounts[feature] != 1 {
			return fmt.Errorf("stable corpus must contain exactly one %s case", feature)
		}
	}
	return nil
}

func hasExpectedCapabilityContract(corpusCase Case, exit int, name, status, reason string) bool {
	for _, scenario := range corpusCase.Scenarios {
		if !scenario.Expect.AllowPartial || !slices.Contains(scenario.Expect.AllowedExits, exit) {
			continue
		}
		for _, capability := range scenario.Expect.Capabilities {
			if capability.Name == name && capability.Status == status &&
				strings.Contains(capability.ReasonContains, reason) {
				return true
			}
		}
	}
	return false
}

func (s Scenario) validate() error {
	if !slugPattern.MatchString(s.Name) {
		return errors.New("name must be a lowercase path-safe slug")
	}
	if s.Repeat < 0 || s.Repeat > 2 {
		return errors.New("repeat must be 1 or 2 when set")
	}
	for i := 0; i < len(s.Args); i++ {
		switch s.Args[i] {
		case "--stack":
			i++
			if i >= len(s.Args) || (s.Args[i] != "node" && s.Args[i] != "python") {
				return errors.New("--stack requires node or python")
			}
		case "--only":
			i++
			if i >= len(s.Args) || (s.Args[i] != "packages" && s.Args[i] != "vulnerabilities") {
				return errors.New("--only requires packages or vulnerabilities")
			}
		default:
			return fmt.Errorf("argument %q is not allowed in corpus scenarios", s.Args[i])
		}
	}
	if err := s.Expect.validate(); err != nil {
		return err
	}
	return nil
}

func (e Expectation) validate() error {
	for _, status := range e.AllowedStatuses {
		if !slices.Contains([]string{"clean", "ready", "findings", "scan-only", "partial"}, status) {
			return fmt.Errorf("expect.allowed_statuses contains unsupported value %q", status)
		}
	}
	for _, code := range e.AllowedExits {
		if code < 0 || code > 7 {
			return fmt.Errorf("expect.allowed_exit_codes contains unsupported value %d", code)
		}
	}
	for _, capability := range e.Capabilities {
		if capability.Name == "" || capability.Status == "" ||
			strings.ContainsAny(capability.Name+capability.Status+capability.ReasonContains, "\x00\r\n") {
			return errors.New("expected capability fields must be bounded single-line values")
		}
		if len(capability.Name) > 64 || len(capability.Status) > 64 || len(capability.ReasonContains) > 256 {
			return errors.New("expected capability fields exceed their limits")
		}
	}
	if (e.AllowPartial || len(e.AllowedExits) > 0 || len(e.AllowedStatuses) > 0) && len(e.Capabilities) == 0 {
		return errors.New("non-default expectations require an exact capability contract")
	}
	return nil
}

// EffectiveRepeat returns the number of consecutive passes for a scenario.
func (s Scenario) EffectiveRepeat() int {
	if s.Repeat == 0 {
		return 2
	}
	return s.Repeat
}

// ValidateGitHubURL accepts only canonical public repository URLs.
func ValidateGitHubURL(raw string) error {
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return errors.New("must be a canonical HTTPS GitHub repository URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.RawPath != "" {
		return errors.New("must be canonical https://github.com/<owner>/<repo> without credentials, query, or fragment")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 2 || !githubPartPattern.MatchString(parts[0]) ||
		!githubPartPattern.MatchString(parts[1]) || strings.HasSuffix(parts[1], ".git") {
		return errors.New("must contain exactly one GitHub owner and repository")
	}
	if parsed.Path != "/"+parts[0]+"/"+parts[1] || parsed.String() != raw {
		return errors.New("must use canonical GitHub URL spelling")
	}
	return nil
}

func validateSubdir(value string) error {
	if value == "" {
		return nil
	}
	if strings.ContainsAny(value, "\x00\\\r\n") || strings.HasPrefix(value, "/") ||
		path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") ||
		strings.Contains(value, "/../") {
		return errors.New("subdir must be an empty or normalized safe relative path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("subdir must be an empty or normalized safe relative path")
		}
	}
	return nil
}
