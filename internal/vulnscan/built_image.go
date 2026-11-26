package vulnscan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

// ImageArtifact identifies a published artifact. SHA is supplied by the caller;
// scanning a digest does not attest its source commit or deployment.
type ImageArtifact struct {
	Project  string `json:"project"`
	SHA      string `json:"sha"`
	Image    string `json:"image"`
	Platform string `json:"platform"`
}

// ProductionImage is an allowlisted metadata export, never server access.
type ProductionImage struct {
	ImageArtifact
	ObservedAt time.Time `json:"observed_at"`
}

// BuiltImageInput is the version-1 CI/inventory interchange contract.
type BuiltImageInput struct {
	SchemaVersion int              `json:"schema_version"`
	Artifact      ImageArtifact    `json:"artifact"`
	Production    *ProductionImage `json:"production,omitempty"`
}

// ImageCoverage records detected package metadata, not universal completeness.
type ImageCoverage struct {
	OS        string `json:"os"`
	Libraries string `json:"libraries"`
}

// BuiltImageReport is independent of repository/base-image scan reports.
// Only status=clean or findings is a successful scan; partial and failed must
// never be interpreted as absence of vulnerabilities.
type BuiltImageReport struct {
	SchemaVersion        int              `json:"schema_version"`
	Artifact             ImageArtifact    `json:"artifact"`
	Production           *ProductionImage `json:"production,omitempty"`
	ProductionComparison string           `json:"production_comparison"`
	ScannedAt            time.Time        `json:"scanned_at"`
	ScannerImage         string           `json:"scanner_image"`
	DatabaseUpdatedAt    *time.Time       `json:"database_updated_at,omitempty"`
	DatabaseMaxAgeHours  int              `json:"database_max_age_hours"`
	Coverage             ImageCoverage    `json:"coverage"`
	Status               string           `json:"status"`
	Error                string           `json:"error,omitempty"`
	Findings             []JSONFinding    `json:"findings"`
}

var (
	imageRepository = regexp.MustCompile(`^(ghcr\.io|registry-1\.docker\.io)/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$`)
	artifactSHA     = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	artifactProject = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$`)
)

// DecodeBuiltImageInput accepts only bounded JSON from an explicit metadata
// stream. It never opens a path or discovers machine/repository configuration.
func DecodeBuiltImageInput(reader io.Reader) (BuiltImageInput, error) {
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return BuiltImageInput{}, errors.New("image metadata exceeds its input limit or cannot be read")
	}
	var input BuiltImageInput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return BuiltImageInput{}, errors.New("invalid image metadata JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return BuiltImageInput{}, errors.New("image metadata must contain one JSON document")
	}
	return input, nil
}

// ValidateBuiltImageInput checks exact repository authority independently of
// the untrusted metadata. Only anonymous registries supported by managed
// egress are admitted; credentials and mutable tags have no input contract.
func ValidateBuiltImageInput(input BuiltImageInput, repositories []string, now time.Time) error {
	if input.SchemaVersion != 1 || len(repositories) == 0 || len(repositories) > 64 {
		return errors.New("image schema version 1 and an explicit repository allowlist are required")
	}
	allowed := make(map[string]bool)
	for _, repository := range repositories {
		if !imageRepository.MatchString(repository) {
			return errors.New("repository allowlist requires canonical public ghcr.io or registry-1.docker.io repositories")
		}
		allowed[repository] = true
	}
	validate := func(artifact ImageArtifact) error {
		parts := strings.Split(artifact.Image, "@")
		if !artifactProject.MatchString(artifact.Project) || !artifactSHA.MatchString(artifact.SHA) ||
			len(parts) != 2 || !allowed[parts[0]] || !exactDigest.MatchString(artifact.Image) ||
			(artifact.Platform != "linux/amd64" && artifact.Platform != "linux/arm64") {
			return errors.New("image requires project, full commit SHA, allowlisted repository@sha256 and linux/amd64 or linux/arm64")
		}
		return nil
	}
	if err := validate(input.Artifact); err != nil {
		return err
	}
	if input.Production != nil {
		if err := validate(input.Production.ImageArtifact); err != nil {
			return err
		}
		if input.Production.Project != input.Artifact.Project || input.Production.ObservedAt.IsZero() || input.Production.ObservedAt.After(now.Add(5*time.Minute)) {
			return errors.New("production metadata requires the same project and a valid observation time")
		}
	}
	return nil
}

// ScanBuiltImage scans the merged published image, including application
// layers, through the existing isolated Trivy boundary. On error it returns
// a usable report with explicit failure/coverage, never a clean result.
func (s Scanner) ScanBuiltImage(ctx context.Context, input BuiltImageInput, repositories []string, cfg config.Config) (BuiltImageReport, error) {
	report := BuiltImageReport{
		SchemaVersion: 1, Artifact: input.Artifact, Production: input.Production,
		ProductionComparison: "not_provided", ScannedAt: s.now().UTC(),
		ScannerImage: cfg.VulnScan.ImageScan.Image, DatabaseMaxAgeHours: cfg.VulnScan.DatabaseMaxAgeHours,
		Coverage: ImageCoverage{OS: "unknown", Libraries: "unknown"}, Status: "failed", Findings: []JSONFinding{},
	}
	failure := func(code string) (BuiltImageReport, error) {
		report.Error = code
		return report, errors.New(code)
	}
	if err := ValidateBuiltImageInput(input, repositories, s.now()); err != nil {
		return failure("invalid_image_input")
	}
	if input.Production != nil {
		report.ProductionComparison = "different"
		if input.Artifact == input.Production.ImageArtifact {
			report.ProductionComparison = "matches_export"
		}
	}
	if !exactDigest.MatchString(report.ScannerImage) || report.DatabaseMaxAgeHours < 1 || report.DatabaseMaxAgeHours > 168 {
		return failure("invalid_scanner_configuration")
	}
	if s.database == nil {
		s.database = &databaseSession{}
	}
	bundle, err := emptyImageBundle()
	if err != nil {
		return failure("image_input_archive_failed")
	}
	defer bundle.Destroy()
	cache, err := s.ensureTrivyDatabase(ctx, bundle, report.ScannerImage, cfg.Update.Egress, report.DatabaseMaxAgeHours)
	if err != nil {
		return failure("database_unavailable")
	}
	out, err := s.trivyCommand(ctx, bundle, report.ScannerImage, cfg.Update.Egress, report.DatabaseMaxAgeHours,
		"image", "--config", "/dev/null", "--ignorefile", "/dev/null", "--scanners", "vuln",
		"--pkg-types", "os,library", "--list-all-pkgs", "--include-dev-deps", "--image-src", "remote",
		"--cache-backend", "memory", "--format", "json", "--platform", input.Artifact.Platform, input.Artifact.Image)
	if err != nil {
		return failure("image_scan_failed")
	}
	findings, updated, _, err := parseTrivy(out)
	if err != nil {
		return failure("invalid_image_report")
	}
	if updated.IsZero() {
		updated = cache.updatedAt
	}
	if updated.IsZero() || checkDatabaseAge(updated, report.DatabaseMaxAgeHours, s.now()) != nil {
		return failure("database_not_fresh")
	}
	report.DatabaseUpdatedAt = &updated
	for i := range findings {
		findings[i].Kind = "image"
		findings[i].Image = input.Artifact.Image
	}
	report.Findings = StructuredFindings(findings)
	coverage, err := builtImageCoverage(out, input.Artifact)
	report.Coverage = coverage
	if err != nil {
		report.Status = "partial"
		return failure("image_metadata_incomplete_or_mismatched")
	}
	report.Status = "clean"
	if len(report.Findings) > 0 {
		report.Status = "findings"
	}
	return report, nil
}

func emptyImageBundle() (scaninput.Bundle, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "project/", Typeflag: tar.TypeDir, Mode: 0o555, Uid: 65532, Gid: 65532}); err != nil {
		return scaninput.Bundle{}, err
	}
	if err := writer.Close(); err != nil {
		return scaninput.Bundle{}, err
	}
	return scaninput.Bundle{Archive: buffer.Bytes()}, nil
}

func builtImageCoverage(data []byte, artifact ImageArtifact) (ImageCoverage, error) {
	coverage := ImageCoverage{OS: "missing_metadata", Libraries: "missing_metadata"}
	var doc struct {
		SchemaVersion int
		ArtifactType  string
		Metadata      struct {
			RepoDigests []string
			OS          struct {
				Family, Name string
				EOSL         bool
			}
			ImageConfig struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			}
		}
		Results []struct {
			Class, Type, Target string
			Packages            []struct{ Name, Version string }
		}
	}
	if json.Unmarshal(data, &doc) != nil || doc.SchemaVersion != 2 || doc.ArtifactType != "container_image" {
		return coverage, errors.New("invalid image report identity")
	}
	matched := false
	for _, digest := range doc.Metadata.RepoDigests {
		if digest == artifact.Image {
			matched = true
		}
	}
	if !matched || doc.Metadata.ImageConfig.OS+"/"+doc.Metadata.ImageConfig.Architecture != artifact.Platform {
		return coverage, errors.New("image digest or platform mismatch")
	}
	for _, result := range doc.Results {
		valid := result.Target != "" && result.Type != "" && len(result.Packages) > 0
		for _, pkg := range result.Packages {
			valid = valid && pkg.Name != "" && pkg.Version != ""
		}
		if !valid {
			return coverage, errors.New("incomplete package metadata")
		}
		switch result.Class {
		case "os-pkgs":
			if doc.Metadata.OS.Family != "" && doc.Metadata.OS.Name != "" {
				coverage.OS = "detected"
			}
		case "lang-pkgs":
			coverage.Libraries = "detected"
		default:
			return coverage, errors.New("unexpected package result class")
		}
	}
	if doc.Metadata.OS.EOSL {
		coverage.OS = "end_of_support"
	}
	if coverage.OS != "detected" || coverage.Libraries != "detected" {
		return coverage, errors.New("image package coverage is incomplete")
	}
	return coverage, nil
}
