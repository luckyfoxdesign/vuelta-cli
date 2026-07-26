// Package vulnscan runs pinned Trivy and/or OSV-Scanner containers for CVE
// scanning of dependencies and built images.
package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/scancontainer"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

// Output bounds for untrusted scanner output (F5-MED-008). Scanner stdout is
// a JSON report that must be parsed in full, so it gets a generous hard cap:
// exceeding it kills the docker client and fails the scan instead of parsing
// a truncated document. Stderr is diagnostics only and keeps a bounded tail.
const (
	scannerStdoutMaxBytes  = 64 << 20
	scannerStderrTailBytes = 64 << 10
)

// Finding is a normalized CVE/GHSA finding. It intentionally retains the
// installed and fixed versions so an audit can distinguish a remediation from
// a newly introduced or worsened issue.
type Finding struct {
	ID               string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Target           string
	Source           string
}

// Key identifies the same affected package version across baseline and
// post-update scans.
func (f Finding) Key() string {
	return strings.Join([]string{f.ID, f.Package, f.InstalledVersion, f.Target, f.Source}, "\x00")
}

// Ref is the safe, terse identifier suitable for a commit summary or
// notification; raw scanner output is never forwarded.
func (f Finding) Ref() string { return f.ID }

// Report is one complete local scanner run. A non-nil error always means the
// caller must fail closed; an empty Findings slice is valid only after a
// successfully parsed, fresh scanner report.
type Report struct {
	Findings         []Finding
	Suppressed       []Finding
	ImageResolutions []ImageResolution
	ImageSkips       []ImageSkip
}

// ImageTier is the resolution ladder rung an image reference was scanned at.
type ImageTier int

const (
	// TierExactDigest is a digest already pinned in config or a Dockerfile/
	// compose file; scanned as-is, unchanged from prior behavior.
	TierExactDigest ImageTier = 1
	// TierExplicitTag is a tag reference explicitly declared as the deployed
	// artifact, either via compose "image:" or docker_images.runtime_images.
	TierExplicitTag ImageTier = 2
	// TierBaseImageTag is a Dockerfile "FROM <tag>" reference scanned as a
	// proxy for a built image ("build: ." in compose); the base image, not
	// the artifact actually deployed.
	TierBaseImageTag ImageTier = 3
)

// ImageResolution records what was actually scanned for one image intent at
// one platform: the configured/detected reference, the digest it resolved
// to, and the tier that resolution claim rests on.
type ImageResolution struct {
	Reference           string
	ResolvedDigest      string
	Platform            string
	Tier                ImageTier
	Dockerfile          string
	OSPackagesInstalled bool
	ResolvedAt          time.Time
}

// ImageSkip is a structured tier-4 capability outcome: an image intent that
// could not be resolved to any digest (unreachable registry, no image
// reference at all, or an unresolvable reference such as "FROM scratch").
// It is always a visible, structured outcome, never a bare warning string.
type ImageSkip struct {
	Reference string
	Reason    string
}

// Command runs a scanner command. It is injectable so scanner parsing and
// gate behavior can be tested without a daemon or a network connection.
type Command func(ctx context.Context, dir, name string, args ...string) ([]byte, error)

// ProgressFunc synchronously reports one observable scanner step. Callers
// must return quickly; a nil callback disables progress entirely.
type ProgressFunc func(detail string, done, total int)

// ScannerOption configures optional scanner observability without changing
// the Scan or ScanImages library contracts.
type ScannerOption func(*Scanner)

// WithDependencyProgress reports dependency input/scanner steps.
func WithDependencyProgress(progress ProgressFunc) ScannerOption {
	return func(scanner *Scanner) {
		scanner.dependencyProgress = progress
	}
}

// WithImageProgress reports image input and per-reference/platform steps.
func WithImageProgress(progress ProgressFunc) ScannerOption {
	return func(scanner *Scanner) {
		scanner.imageProgress = progress
	}
}

// Scanner invokes Trivy/OSV and validates their structured output.
type Scanner struct {
	Command              Command
	Docker               dockerexec.Runner
	Now                  func() time.Time
	allowUntrackedInputs bool
	dependencyProgress   ProgressFunc
	imageProgress        ProgressFunc
}

// NewAdhocScanner returns the narrow scanner used only for an explicit
// unregistered directory. Registered pipeline callers use the zero-value
// Scanner, which always requires tracked inputs.
func NewAdhocScanner(command Command, options ...ScannerOption) Scanner {
	scanner := Scanner{Command: command, allowUntrackedInputs: true}
	for _, option := range options {
		option(&scanner)
	}
	return scanner
}

// NewReadOnlyScanner returns the container scanner used by the read-only scan
// command. Scan inputs remain allowlisted and secret-like names are rejected,
// but Git tracking is deferred to snapshot creation so a dirty honest project
// can still receive vulnerability findings.
func NewReadOnlyScanner(options ...ScannerOption) Scanner {
	scanner := Scanner{allowUntrackedInputs: true}
	for _, option := range options {
		option(&scanner)
	}
	return scanner
}

func (s Scanner) command(ctx context.Context, bundle scaninput.Bundle, image string, egressConfig config.EgressConfig, name string, args ...string) ([]byte, error) {
	if s.Command != nil {
		private, err := scaninput.MaterializePrivate(ctx, bundle)
		if err != nil {
			return nil, err
		}
		output, commandErr := s.Command(ctx, private.Dir, name, args...)
		return output, errors.Join(commandErr, private.Close())
	}
	docker := s.Docker
	if docker == nil {
		docker = dockerexec.Default()
	}
	return dockerCommandWith(ctx, docker, bundle, image, egressConfig, name, args...)
}

// dockerCommand runs a scanner with no host mount. The minimal input archive
// is copied through stdin before the read-only container starts.
func dockerCommand(ctx context.Context, bundle scaninput.Bundle, image string, egressConfig config.EgressConfig, name string, args ...string) ([]byte, error) {
	return dockerCommandWith(ctx, dockerexec.Default(), bundle, image, egressConfig, name, args...)
}

func dockerCommandWith(ctx context.Context, docker dockerexec.Runner, bundle scaninput.Bundle, image string, egressConfig config.EgressConfig, name string, args ...string) ([]byte, error) {
	if !exactDigest.MatchString(image) {
		return nil, fmt.Errorf("scanner image %q is not pinned to an exact digest", image)
	}
	network, proxyURL, err := egress.ResolveWith(ctx, egressConfig, docker)
	if err != nil {
		return nil, err
	}
	toolEnvironment := ""
	if name == "trivy" {
		toolEnvironment = name
	}
	result, err := (scancontainer.Runner{Docker: docker}).Run(ctx, scancontainer.Request{
		Image: image, Args: args, Archive: bundle.Archive, Network: network, Proxy: proxyURL, Tool: toolEnvironment,
		Memory: "2g", Tmpfs: "2g",
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: scannerStdoutMaxBytes},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: scannerStderrTailBytes},
	})
	var limitErr *dockerexec.OutputLimitError
	if errors.As(err, &limitErr) {
		return nil, fmt.Errorf("docker run %s %s: report exceeded %d bytes", name, strings.Join(args, " "), scannerStdoutMaxBytes)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("docker run %s %s: %w", name, strings.Join(args, " "), err)
	}
	return result.Stdout, nil
}

func (s Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Scan checks dependency lock files with the selected local scanner and, for
// Docker workspaces, every exact digest referenced by docker_images.files. No
// scanner ignore flag is ever used: tracked policy is evaluated afterwards.
func (s Scanner) Scan(ctx context.Context, root string, ws config.Workspace, cfg config.Config) (Report, error) {
	scanConfig := cfg.VulnScan
	if root == "" {
		return Report{}, errors.New("scan root is required")
	}
	policy, err := loadPolicy(ctx, ws.Path, scanConfig.PolicyFile, s.now(), !s.allowUntrackedInputs)
	if err != nil {
		return Report{}, err
	}

	findings, err := s.scanDependencies(ctx, root, ws, cfg)
	if err != nil {
		return Report{}, err
	}
	imageFindings, resolutions, skips, err := s.scanImages(ctx, root, ws, cfg)
	if err != nil {
		return Report{}, err
	}
	report := applyPolicy(append(findings, imageFindings...), policy)
	report.ImageResolutions = resolutions
	report.ImageSkips = skips
	return report, nil
}

// ScanImages checks configured immutable images without scanning repository
// dependencies. It lets the security gate retain image coverage when
// github-dependabot is selected as the dependency source.
func (s Scanner) ScanImages(ctx context.Context, root string, ws config.Workspace, cfg config.Config) (Report, error) {
	if root == "" {
		return Report{}, errors.New("scan root is required")
	}
	policy, err := loadPolicy(ctx, ws.Path, cfg.VulnScan.PolicyFile, s.now(), !s.allowUntrackedInputs)
	if err != nil {
		return Report{}, err
	}
	findings, resolutions, skips, err := s.scanImages(ctx, root, ws, cfg)
	if err != nil {
		return Report{}, err
	}
	report := applyPolicy(findings, policy)
	report.ImageResolutions = resolutions
	report.ImageSkips = skips
	return report, nil
}

func (s Scanner) scanDependencies(ctx context.Context, root string, ws config.Workspace, cfg config.Config) ([]Finding, error) {
	scanConfig := cfg.VulnScan
	contract, err := scaninput.DependencyContract(ws)
	if err != nil {
		return nil, err
	}
	repositoryRoot := ws.Path
	if repositoryRoot == "" {
		repositoryRoot = root
	}
	bundle, err := scaninput.Build(ctx, root, repositoryRoot, scaninput.Options{RequireTracked: !s.allowUntrackedInputs}, contract)
	if err != nil {
		return nil, err
	}
	defer bundle.Destroy()
	switch scanConfig.DependencySource {
	case "trivy":
		if s.dependencyProgress != nil {
			s.dependencyProgress("trivy fs", 1, 1)
		}
		out, err := s.command(ctx, bundle, scanConfig.Image, cfg.Update.Egress, "trivy", "fs", "--scanners", "vuln", "--include-dev-deps", "--format", "json", "/project")
		if err != nil {
			return nil, fmt.Errorf("trivy filesystem scan: %w", err)
		}
		parsed, updated, _, err := parseTrivy(out)
		if err != nil {
			return nil, fmt.Errorf("trivy filesystem scan: %w", err)
		}
		if err := checkDatabaseAge(freshDatabaseTimestamp(updated, s.now()), scanConfig.DatabaseMaxAgeHours, s.now()); err != nil {
			return nil, fmt.Errorf("trivy filesystem scan: %w", err)
		}
		return parsed, nil
	case "osv-scanner":
		if s.dependencyProgress != nil {
			s.dependencyProgress("osv-scanner", 1, 1)
		}
		out, err := s.command(ctx, bundle, scanConfig.Image, cfg.Update.Egress, "osv-scanner", "--format", "json", "--lockfile", "/project")
		if err != nil {
			return nil, fmt.Errorf("osv-scanner filesystem scan: %w", err)
		}
		parsed, updated, err := parseOSV(out)
		if err != nil {
			return nil, fmt.Errorf("osv-scanner filesystem scan: %w", err)
		}
		if err := checkDatabaseAge(updated, scanConfig.DatabaseMaxAgeHours, s.now()); err != nil {
			return nil, fmt.Errorf("osv-scanner filesystem scan: %w", err)
		}
		return parsed, nil
	default:
		return nil, fmt.Errorf("unsupported local dependency scanner %q", scanConfig.DependencySource)
	}
}

func (s Scanner) scanImages(ctx context.Context, root string, ws config.Workspace, cfg config.Config) ([]Finding, []ImageResolution, []ImageSkip, error) {
	scanConfig := cfg.VulnScan
	if !scanConfig.ImageScan.Enabled || ws.DockerImages == nil {
		return nil, nil, nil, nil
	}
	if scanConfig.ImageScan.Tool != "trivy" {
		return nil, nil, nil, fmt.Errorf("unsupported image scanner %q", scanConfig.ImageScan.Tool)
	}
	repositoryRoot := ws.Path
	if repositoryRoot == "" {
		repositoryRoot = root
	}
	if s.imageProgress != nil {
		s.imageProgress("Preparing scan input", 0, 0)
	}
	bundle, err := scaninput.Build(ctx, root, repositoryRoot, scaninput.Options{RequireTracked: !s.allowUntrackedInputs}, scaninput.DockerContract(ws))
	if err != nil {
		return nil, nil, nil, err
	}
	defer bundle.Destroy()
	intents, err := collectImageIntents(bundle, ws.DockerImages.Files, ws.DockerImages.RuntimeImages)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(intents) == 0 {
		return nil, nil, []ImageSkip{{
			Reason: "no image reference was found in the configured Dockerfile(s) or compose file(s)",
		}}, nil
	}
	var findings []Finding
	var resolutions []ImageResolution
	var skips []ImageSkip
	platforms := imagePlatforms(ws, scanConfig)
	total := len(intents) * len(platforms)
	step := 0
	for _, intent := range intents {
		args := []string{"image", "--scanners", "vuln", "--pkg-types", "os", "--format", "json"}
		if scanConfig.ImageScan.VEX == "auto" {
			args = append(args, "--vex", "repo")
		}
		for _, platform := range platforms {
			step++
			if s.imageProgress != nil {
				s.imageProgress(intent.Reference+" ("+platform+")", step, total)
			}
			imageArgs := append(append([]string{}, args...), "--image-src", "registry", "--platform", platform, intent.Reference)
			out, cmdErr := s.command(ctx, bundle, scanConfig.ImageScan.Image, cfg.Update.Egress, "trivy", imageArgs...)
			if cmdErr != nil {
				if intent.Tier == TierExactDigest {
					return nil, nil, nil, fmt.Errorf("trivy image scan %s (%s): %w", intent.Reference, platform, cmdErr)
				}
				skips = append(skips, ImageSkip{
					Reference: intent.Reference,
					Reason:    fmt.Sprintf("could not resolve %s for platform %s: %v", intent.Reference, platform, cmdErr),
				})
				continue
			}
			parsed, updated, metadata, parseErr := parseTrivy(out)
			if parseErr != nil {
				return nil, nil, nil, fmt.Errorf("trivy image scan %s: %w", intent.Reference, parseErr)
			}
			if ageErr := checkDatabaseAge(freshDatabaseTimestamp(updated, s.now()), scanConfig.DatabaseMaxAgeHours, s.now()); ageErr != nil {
				return nil, nil, nil, fmt.Errorf("trivy image scan %s: %w", intent.Reference, ageErr)
			}
			findings = append(findings, parsed...)
			digest, ok := extractRepoDigest(metadata.RepoDigests)
			if !ok {
				digest = intent.Reference
			}
			resolutions = append(resolutions, ImageResolution{
				Reference: intent.Reference, ResolvedDigest: digest, Platform: platform, Tier: intent.Tier,
				Dockerfile: intent.Dockerfile, OSPackagesInstalled: intent.OSPackagesInstalled, ResolvedAt: s.now(),
			})
		}
	}
	return findings, resolutions, skips, nil
}

func imagePlatforms(ws config.Workspace, cfg config.VulnScanConfig) []string {
	if len(ws.DockerImages.Platforms) > 0 {
		return ws.DockerImages.Platforms
	}
	if len(cfg.ImageScan.Platforms) > 0 {
		return cfg.ImageScan.Platforms
	}
	return []string{"linux/amd64"}
}

var (
	// fromReference captures a Dockerfile "FROM <ref>" base image and, if
	// present, its "AS <name>" build-stage alias. A later FROM referencing
	// that alias points at an internal build stage, not an external image.
	fromReference  = regexp.MustCompile(`(?im)^\s*FROM(?:\s+--[^\s]+)*\s+(\S+)(?:\s+[Aa][Ss]\s+(\S+))?`)
	imageReference = regexp.MustCompile(`(?im)^\s*image:\s*([^\s#]+)`)
	exactDigest    = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	// osPackageInstallPattern statically detects a Dockerfile RUN line that
	// installs OS packages, which weakens a base image's claim to represent
	// the built artifact's OS package surface (tier-3 honesty downgrade).
	osPackageInstallPattern = regexp.MustCompile(`(?im)^\s*RUN\s.*\b(?:apk\s+add|apt(?:-get)?\s+install|yum\s+install|dnf\s+install|microdnf\s+install)\b`)
)

// imageIntent is one image reference collected as scan input, tagged with
// the resolution-ladder tier its scan result may claim.
type imageIntent struct {
	Reference           string
	Tier                ImageTier
	Dockerfile          string
	OSPackagesInstalled bool
}

// collectImageIntents gathers every image reference declared across the
// configured Docker inputs as scan-time intent. An exact digest is scanned
// as-is (tier 1); an explicit compose "image:" or a configured
// docker_images.runtime_images entry is the strongest tag claim (tier 2); a
// Dockerfile "FROM <tag>" is only a base-image proxy (tier 3). It never
// errors on an unpinned reference: resolution and any unresolvable skip
// happen later, per image, during the scan itself.
func collectImageIntents(bundle scaninput.Bundle, files, runtimeImages []string) ([]imageIntent, error) {
	intents := make(map[string]imageIntent)
	add := func(reference string, tier ImageTier, dockerfile string, osPackagesInstalled bool) {
		if exactDigest.MatchString(reference) {
			tier = TierExactDigest
		}
		if existing, ok := intents[reference]; ok && existing.Tier <= tier {
			return
		}
		intents[reference] = imageIntent{Reference: reference, Tier: tier, Dockerfile: dockerfile, OSPackagesInstalled: osPackagesInstalled}
	}
	for _, rel := range files {
		data, ok := bundle.Content(rel)
		if !ok {
			return nil, fmt.Errorf("validated image scan input %s is unavailable", rel)
		}
		content := string(data)
		for _, match := range imageReference.FindAllStringSubmatch(content, -1) {
			add(match[1], TierExplicitTag, "", false)
		}
		osPackagesInstalled := osPackageInstallPattern.MatchString(content)
		stageNames := make(map[string]bool)
		for _, match := range fromReference.FindAllStringSubmatch(content, -1) {
			reference := match[1]
			if !stageNames[strings.ToLower(reference)] && !strings.EqualFold(reference, "scratch") {
				add(reference, TierBaseImageTag, rel, osPackagesInstalled)
			}
			if len(match) > 2 && match[2] != "" {
				stageNames[strings.ToLower(match[2])] = true
			}
		}
	}
	for _, image := range runtimeImages {
		add(image, TierExplicitTag, "", false)
	}
	result := make([]imageIntent, 0, len(intents))
	for _, intent := range intents {
		result = append(result, intent)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Reference < result[j].Reference })
	return result, nil
}

// extractRepoDigest reads the resolved manifest digest Trivy reports for the
// image it just scanned (populated even when Trivy was given a tag, since
// resolving that tag to a manifest digest is required to pull it). This
// reuses Trivy's own registry resolution rather than adding a separate
// resolution call over a new path.
func extractRepoDigest(repoDigests []string) (string, bool) {
	for _, repoDigest := range repoDigests {
		if index := strings.LastIndex(repoDigest, "@sha256:"); index >= 0 {
			return repoDigest[index+1:], true
		}
	}
	return "", false
}

// trivyMetadata carries the subset of Trivy's image scan Metadata needed to
// record what was actually scanned; it is empty for filesystem scans.
type trivyMetadata struct {
	RepoDigests []string
}

type trivyDocument struct {
	Metadata struct {
		DBUpdatedAt string `json:"DBUpdatedAt"`
		UpdatedAt   string `json:"UpdatedAt"`
		Database    struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"Database"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			ID               string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivy(data []byte) ([]Finding, time.Time, trivyMetadata, error) {
	var doc trivyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, time.Time{}, trivyMetadata{}, fmt.Errorf("parse JSON: %w", err)
	}
	var updated time.Time
	if value := firstNonEmpty(doc.Metadata.DBUpdatedAt, doc.Metadata.Database.UpdatedAt, doc.Metadata.UpdatedAt); value != "" {
		var err error
		updated, err = parseTimestamp(value)
		if err != nil {
			return nil, time.Time{}, trivyMetadata{}, fmt.Errorf("scanner database timestamp: %w", err)
		}
	}
	var findings []Finding
	for _, result := range doc.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "" || vuln.PkgName == "" || vuln.InstalledVersion == "" || vuln.Severity == "" {
				return nil, time.Time{}, trivyMetadata{}, errors.New("scanner returned an incomplete vulnerability finding")
			}
			findings = append(findings, Finding{ID: vuln.ID, Package: vuln.PkgName, InstalledVersion: vuln.InstalledVersion, FixedVersion: vuln.FixedVersion, Severity: strings.ToUpper(vuln.Severity), Target: result.Target, Source: "trivy"})
		}
	}
	return normalize(findings), updated, trivyMetadata{RepoDigests: doc.Metadata.RepoDigests}, nil
}

// freshDatabaseTimestamp accepts current Trivy reports that omit DB metadata.
// dockerRunArgs always provides an empty tmpfs cache, so a successful scan has
// necessarily fetched its database during this invocation.
func freshDatabaseTimestamp(updated, now time.Time) time.Time {
	if updated.IsZero() {
		return now
	}
	return updated
}

// OSV's output schema deliberately carries no scanner-cache timestamp in
// many versions. It may expose DatabaseUpdatedAt in wrapper tooling; when it
// does not, parseOSV rejects the output rather than guessing freshness.
func parseOSV(data []byte) ([]Finding, time.Time, error) {
	var doc struct {
		DatabaseUpdatedAt string `json:"database_updated_at"`
		Results           []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Groups []struct {
					IDs      []string `json:"ids"`
					Packages []struct {
						Version string `json:"version"`
					} `json:"packages"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse JSON: %w", err)
	}
	updated, err := parseTimestamp(doc.DatabaseUpdatedAt)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("scanner database timestamp: %w", err)
	}
	var findings []Finding
	for _, result := range doc.Results {
		for _, pkg := range result.Packages {
			for _, group := range pkg.Groups {
				for _, id := range group.IDs {
					for _, affected := range group.Packages {
						if id == "" || pkg.Package.Name == "" || affected.Version == "" {
							return nil, time.Time{}, errors.New("scanner returned an incomplete vulnerability finding")
						}
						findings = append(findings, Finding{ID: id, Package: pkg.Package.Name, InstalledVersion: affected.Version, Severity: "UNKNOWN", Target: result.Source.Path, Source: "osv-scanner"})
					}
				}
			}
		}
	}
	return normalize(findings), updated, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("missing database timestamp")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %q: %w", value, err)
	}
	return parsed, nil
}

func checkDatabaseAge(updated time.Time, maxHours int, now time.Time) error {
	if updated.After(now.Add(5 * time.Minute)) {
		return errors.New("database timestamp is in the future")
	}
	if now.Sub(updated) > time.Duration(maxHours)*time.Hour {
		return fmt.Errorf("database is older than %d hours", maxHours)
	}
	return nil
}

type policyFile struct {
	Exceptions []policyException `yaml:"exceptions"`
}

type policyException struct {
	ID      string `yaml:"id"`
	Package string `yaml:"package"`
	Reason  string `yaml:"reason"`
	Owner   string `yaml:"owner"`
	Expires string `yaml:"expires"`
}

func loadPolicy(ctx context.Context, projectRoot, rel string, now time.Time, requireTracked bool) (policyFile, error) {
	if rel == "" {
		return policyFile{}, nil
	}
	bundle, err := scaninput.Build(ctx, projectRoot, projectRoot, scaninput.Options{RequireTracked: requireTracked}, scaninput.PolicyContract(rel))
	if err != nil {
		return policyFile{}, fmt.Errorf("validate vulnerability policy input: %w", err)
	}
	defer bundle.Destroy()
	data, ok := bundle.Content(rel)
	if !ok {
		return policyFile{}, errors.New("validated vulnerability policy input is unavailable")
	}
	var policy policyFile
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return policyFile{}, fmt.Errorf("parse vulnerability policy: %w", err)
	}
	for _, exception := range policy.Exceptions {
		if exception.ID == "" || exception.Package == "" || exception.Reason == "" || exception.Owner == "" || exception.Expires == "" {
			return policyFile{}, errors.New("every vulnerability exception needs id, package, reason, owner, and expires")
		}
		expires, err := time.Parse("2006-01-02", exception.Expires)
		if err != nil || !expires.After(now) {
			return policyFile{}, fmt.Errorf("vulnerability exception %s/%s is expired or invalid", exception.ID, exception.Package)
		}
	}
	return policy, nil
}

func applyPolicy(findings []Finding, policy policyFile) Report {
	var report Report
	for _, finding := range findings {
		suppressed := false
		for _, exception := range policy.Exceptions {
			if exception.ID == finding.ID && exception.Package == finding.Package {
				suppressed = true
				break
			}
		}
		if suppressed {
			report.Suppressed = append(report.Suppressed, finding)
		} else {
			report.Findings = append(report.Findings, finding)
		}
	}
	return report
}

func normalize(findings []Finding) []Finding {
	seen := make(map[string]Finding)
	for _, finding := range findings {
		seen[finding.Key()] = finding
	}
	result := make([]Finding, 0, len(seen))
	for _, finding := range seen {
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key() < result[j].Key() })
	return result
}
