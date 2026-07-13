// Package vulnscan integrates trivy and/or osv-scanner for CVE scanning of
// dependencies and built images.
package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyfoxdesign/vuelta/internal/config"
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
	Findings   []Finding
	Suppressed []Finding
}

// Command runs a scanner command. It is injectable so scanner parsing and
// gate behavior can be tested without a daemon or a network connection.
type Command func(ctx context.Context, dir, name string, args ...string) ([]byte, error)

// Scanner invokes Trivy/OSV and validates their structured output.
type Scanner struct {
	Command Command
	Now     func() time.Time
}

func (s Scanner) command(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	if s.Command != nil {
		return s.Command(ctx, dir, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

func (s Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Scan checks dependency lock files and, for Docker workspaces, every exact
// digest referenced by the explicitly configured docker_images.files. No
// scanner ignore flag is ever used: tracked policy is evaluated afterwards.
func (s Scanner) Scan(ctx context.Context, root string, ws config.Workspace, cfg config.VulnScanConfig) (Report, error) {
	if !cfg.Enabled {
		return Report{}, errors.New("local vulnerability scanner is disabled")
	}
	if root == "" {
		return Report{}, errors.New("scan root is required")
	}
	policy, err := loadPolicy(ctx, ws.Path, cfg.PolicyFile, s.now())
	if err != nil {
		return Report{}, err
	}

	var findings []Finding
	switch cfg.Tool {
	case "trivy":
		out, err := s.command(ctx, root, "trivy", "fs", "--scanners", "vuln", "--format", "json", root)
		if err != nil {
			return Report{}, fmt.Errorf("trivy filesystem scan: %w", err)
		}
		parsed, updated, err := parseTrivy(out)
		if err != nil {
			return Report{}, fmt.Errorf("trivy filesystem scan: %w", err)
		}
		if err := checkDatabaseAge(updated, cfg.DatabaseMaxAgeHours, s.now()); err != nil {
			return Report{}, fmt.Errorf("trivy filesystem scan: %w", err)
		}
		findings = append(findings, parsed...)
	case "osv-scanner":
		out, err := s.command(ctx, root, "osv-scanner", "--format", "json", "--lockfile", root)
		if err != nil {
			return Report{}, fmt.Errorf("osv-scanner filesystem scan: %w", err)
		}
		parsed, updated, err := parseOSV(out)
		if err != nil {
			return Report{}, fmt.Errorf("osv-scanner filesystem scan: %w", err)
		}
		if err := checkDatabaseAge(updated, cfg.DatabaseMaxAgeHours, s.now()); err != nil {
			return Report{}, fmt.Errorf("osv-scanner filesystem scan: %w", err)
		}
		findings = append(findings, parsed...)
	default:
		return Report{}, fmt.Errorf("unsupported local scanner %q", cfg.Tool)
	}

	if cfg.ImageScan.Enabled && ws.DockerImages != nil {
		if cfg.ImageScan.Tool != "trivy" {
			return Report{}, fmt.Errorf("unsupported image scanner %q", cfg.ImageScan.Tool)
		}
		images, err := imageDigests(root, ws.DockerImages.Files, ws.DockerImages.RuntimeImages)
		if err != nil {
			return Report{}, err
		}
		for _, image := range images {
			args := []string{"image", "--scanners", "vuln", "--format", "json"}
			if cfg.ImageScan.VEX == "auto" {
				args = append(args, "--vex", "repo")
			}
			for _, platform := range imagePlatforms(ws, cfg) {
				imageArgs := append(append([]string{}, args...), "--platform", platform, image)
				out, err := s.command(ctx, root, "trivy", imageArgs...)
				if err != nil {
					return Report{}, fmt.Errorf("trivy image scan %s (%s): %w", image, platform, err)
				}
				parsed, updated, err := parseTrivy(out)
				if err != nil {
					return Report{}, fmt.Errorf("trivy image scan %s: %w", image, err)
				}
				if err := checkDatabaseAge(updated, cfg.DatabaseMaxAgeHours, s.now()); err != nil {
					return Report{}, fmt.Errorf("trivy image scan %s: %w", image, err)
				}
				findings = append(findings, parsed...)
			}
		}
	}

	return applyPolicy(findings, policy), nil
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
	fromReference  = regexp.MustCompile(`(?im)^\s*FROM(?:\s+--[^\s]+)*\s+([^\s#]+)`)
	imageReference = regexp.MustCompile(`(?im)^\s*image:\s*([^\s#]+)`)
	exactDigest    = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

func imageDigests(root string, files, runtimeImages []string) ([]string, error) {
	seen := make(map[string]bool)
	for _, rel := range files {
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(filepath.Clean(rel), ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("image scan file %q escapes project root", rel)
		}
		path := filepath.Join(root, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("read image scan file %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("image scan file %s is not a regular file", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read image scan file %s: %w", rel, err)
		}
		for _, pattern := range []*regexp.Regexp{fromReference, imageReference} {
			for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
				if !exactDigest.MatchString(match[1]) {
					return nil, fmt.Errorf("image reference %q in %s is not pinned to an exact digest", match[1], rel)
				}
				seen[match[1]] = true
			}
		}
	}
	for _, image := range runtimeImages {
		if !exactDigest.MatchString(image) {
			return nil, fmt.Errorf("runtime image %q is not pinned to an exact digest", image)
		}
		seen[image] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("no exact image digest found in configured docker_images.files")
	}
	images := make([]string, 0, len(seen))
	for image := range seen {
		images = append(images, image)
	}
	sort.Strings(images)
	return images, nil
}

type trivyDocument struct {
	Metadata struct {
		DBUpdatedAt string `json:"DBUpdatedAt"`
		UpdatedAt   string `json:"UpdatedAt"`
		Database    struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"Database"`
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

func parseTrivy(data []byte) ([]Finding, time.Time, error) {
	var doc trivyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse JSON: %w", err)
	}
	updated, err := parseTimestamp(firstNonEmpty(doc.Metadata.DBUpdatedAt, doc.Metadata.Database.UpdatedAt, doc.Metadata.UpdatedAt))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("scanner database timestamp: %w", err)
	}
	var findings []Finding
	for _, result := range doc.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "" || vuln.PkgName == "" || vuln.InstalledVersion == "" || vuln.Severity == "" {
				return nil, time.Time{}, errors.New("scanner returned an incomplete vulnerability finding")
			}
			findings = append(findings, Finding{ID: vuln.ID, Package: vuln.PkgName, InstalledVersion: vuln.InstalledVersion, FixedVersion: vuln.FixedVersion, Severity: strings.ToUpper(vuln.Severity), Target: result.Target, Source: "trivy"})
		}
	}
	return normalize(findings), updated, nil
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

func loadPolicy(ctx context.Context, projectRoot, rel string, now time.Time) (policyFile, error) {
	if rel == "" {
		return policyFile{}, nil
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(filepath.Clean(rel), ".."+string(filepath.Separator)) {
		return policyFile{}, fmt.Errorf("vulnerability policy %q must be project-relative", rel)
	}
	path := filepath.Join(projectRoot, rel)
	info, err := os.Lstat(path)
	if err != nil {
		return policyFile{}, fmt.Errorf("read vulnerability policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return policyFile{}, errors.New("vulnerability policy must be a regular file")
	}
	cmd := exec.CommandContext(ctx, "git", "ls-files", "--error-unmatch", "--", rel)
	cmd.Dir = projectRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return policyFile{}, fmt.Errorf("vulnerability policy must be tracked: %s", strings.TrimSpace(string(out)))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return policyFile{}, fmt.Errorf("read vulnerability policy: %w", err)
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
