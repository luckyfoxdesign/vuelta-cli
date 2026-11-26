package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
)

const builtRepository = "ghcr.io/example/application"
const builtDigest = builtRepository + "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func builtInput() BuiltImageInput {
	return BuiltImageInput{SchemaVersion: 1, Artifact: ImageArtifact{Project: "api", SHA: strings.Repeat("b", 40), Image: builtDigest, Platform: "linux/amd64"}}
}

func builtConfig() config.Config {
	cfg := *configinit.NewConfig()
	cfg.VulnScan.ImageScan.Image = cfg.VulnScan.Image
	return cfg
}

func builtFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/built-image.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBuiltImageScanContracts(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	fixture := builtFixture(t)
	for _, test := range []struct {
		name, output, status, code string
		commandErr                 error
	}{
		{name: "own application layer vulnerability", output: fixture, status: "findings"},
		{name: "clean with inventory", output: strings.ReplaceAll(fixture, `[{"VulnerabilityID":"CVE-TEST-1","PkgName":"application-dependency","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"HIGH","Layer":{"DiffID":"sha256:own-layer"}}]`, `[]`), status: "clean"},
		{name: "unavailable digest", commandErr: errors.New("manifest unknown"), status: "failed", code: "image_scan_failed"},
		{name: "stale database", output: strings.ReplaceAll(fixture, "2026-11-26T10:00:00Z", "2026-11-20T10:00:00Z"), status: "failed", code: "database_not_fresh"},
		{name: "missing database metadata", output: strings.ReplaceAll(fixture, `"DBUpdatedAt":"2026-11-26T10:00:00Z",`, ""), status: "failed", code: "database_not_fresh"},
		{name: "different architecture", output: strings.ReplaceAll(fixture, `"architecture":"amd64"`, `"architecture":"arm64"`), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "missing package class", output: strings.ReplaceAll(fixture, `"lang-pkgs"`, `""`), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "missing image identity", output: strings.ReplaceAll(fixture, builtDigest, ""), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "missing OS metadata", output: strings.ReplaceAll(fixture, `"Family":"alpine"`, `"Family":""`), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "missing package inventory", output: strings.ReplaceAll(fixture, `"Packages"`, `"OmittedPackages"`), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "unsupported schema", output: strings.ReplaceAll(fixture, `"SchemaVersion":2`, `"SchemaVersion":3`), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "unsupported OS", output: strings.ReplaceAll(fixture, `"Name":"3.22"`, `"Name":"3.22","EOSL":true`), status: "partial", code: "image_metadata_incomplete_or_mismatched"},
		{name: "malformed report", output: `{`, status: "failed", code: "invalid_image_report"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			scanner := Scanner{Now: func() time.Time { return now }, Command: func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
				calls++
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("image scan received repository content: %v %v", entries, err)
				}
				joined := strings.Join(args, " ")
				for _, want := range []string{"--pkg-types os,library", "--image-src remote", "--platform linux/amd64", "--list-all-pkgs", "--config /dev/null", "--ignorefile /dev/null"} {
					if !strings.Contains(joined, want) {
						t.Fatalf("missing %s in %v", want, args)
					}
				}
				if name != "trivy" || args[len(args)-1] != builtDigest {
					t.Fatal("scanner lost immutable identity")
				}
				return []byte(test.output), test.commandErr
			}}
			report, err := scanner.ScanBuiltImage(context.Background(), builtInput(), []string{builtRepository}, builtConfig())
			if (err != nil) != (test.code != "") || report.Status != test.status || report.Error != test.code || calls != 1 {
				t.Fatalf("report=%+v err=%v calls=%d", report, err, calls)
			}
			if test.status == "findings" {
				if len(report.Findings) != 1 || report.Findings[0].Image != builtDigest || report.Findings[0].Package != "application-dependency" {
					t.Fatalf("application layer lost: %+v", report.Findings)
				}
			}
			if report.SchemaVersion != 1 || report.Artifact != builtInput().Artifact || report.ScannedAt != now {
				t.Fatal("missing version/identity/time")
			}
		})
	}
}

func TestBuiltImageProductionComparison(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, field := range []string{"same", "digest", "platform", "sha", "repository"} {
		t.Run(field, func(t *testing.T) {
			input := builtInput()
			input.Production = &ProductionImage{ImageArtifact: input.Artifact, ObservedAt: now.Add(-time.Hour)}
			repositories := []string{builtRepository, "ghcr.io/example/other"}
			switch field {
			case "digest":
				input.Production.Image = builtRepository + "@sha256:" + strings.Repeat("c", 64)
			case "platform":
				input.Production.Platform = "linux/arm64"
			case "sha":
				input.Production.SHA = strings.Repeat("c", 40)
			case "repository":
				input.Production.Image = strings.ReplaceAll(builtDigest, builtRepository, repositories[1])
			}
			scanner := Scanner{Now: func() time.Time { return now }, Command: func(context.Context, string, string, ...string) ([]byte, error) { return []byte(builtFixture(t)), nil }}
			report, err := scanner.ScanBuiltImage(context.Background(), input, repositories, builtConfig())
			want := "different"
			if field == "same" {
				want = "matches_export"
			}
			if err != nil || report.ProductionComparison != want {
				t.Fatalf("%+v %v", report, err)
			}
		})
	}
}

func TestBuiltImageInputRejectsUntrustedAuthority(t *testing.T) {
	for _, image := range []string{"ghcr.io/example/application:latest", "ghcr.io/example/other@sha256:" + strings.Repeat("a", 64), "ghcr.io/example/application:tag@sha256:" + strings.Repeat("a", 64), "https://" + builtDigest, "-" + builtDigest, "ghcr.io/user:password@example/application@sha256:" + strings.Repeat("a", 64)} {
		input := builtInput()
		input.Artifact.Image = image
		if ValidateBuiltImageInput(input, []string{builtRepository}, time.Now()) == nil {
			t.Fatalf("accepted %q", image)
		}
	}
	for _, input := range []string{`{}`, `{"schema_version":2}`, `{"password":"secret"}`, `{}` + `{}`, strings.Repeat(" ", 65537)} {
		decoded, err := DecodeBuiltImageInput(strings.NewReader(input))
		if err == nil {
			err = ValidateBuiltImageInput(decoded, []string{builtRepository}, time.Now())
		}
		if err == nil {
			t.Fatalf("accepted invalid metadata")
		}
	}
	input := builtInput()
	input.Production = &ProductionImage{ImageArtifact: input.Artifact}
	if ValidateBuiltImageInput(input, []string{builtRepository}, time.Now()) == nil {
		t.Fatal("accepted unobserved production metadata")
	}
}

func TestBuiltImageArm64AndJSON(t *testing.T) {
	input := builtInput()
	input.Artifact.Platform = "linux/arm64"
	scanner := Scanner{Now: func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }, Command: func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "--platform linux/arm64") {
			t.Fatal(args)
		}
		return []byte(strings.ReplaceAll(builtFixture(t), `"architecture":"amd64"`, `"architecture":"arm64"`)), nil
	}}
	report, err := scanner.ScanBuiltImage(context.Background(), input, []string{builtRepository}, builtConfig())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"schema_version":1`, `"platform":"linux/arm64"`, `"database_updated_at":`, `"os":"detected"`, `"libraries":"detected"`, `"production_comparison":"not_provided"`} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("missing %s: %s", field, data)
		}
	}
}

func TestBuiltImageUsesVerifiedDatabaseCacheTimestamp(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	cfg := builtConfig()
	session := &databaseSession{}
	updated := now.Add(-2 * time.Hour)
	image := cfg.VulnScan.ImageScan.Image
	session.markReady(trivyDatabaseVolume(image), databaseCache{volume: trivyDatabaseVolume(image), updatedAt: updated})
	scanner := Scanner{Docker: panicDocker{}, database: session, Now: func() time.Time { return now }, databaseCommand: func(_ context.Context, bundle scaninput.Bundle, scannerImage string, _ config.EgressConfig, volume string, initialize bool, name string, args ...string) ([]byte, error) {
		if len(bundle.Archive) == 0 || scannerImage != image || volume != trivyDatabaseVolume(image) || initialize || name != "trivy" || !contains(args, "--skip-db-update") {
			t.Fatalf("invalid database/scanner boundary: %v", args)
		}
		return []byte(strings.ReplaceAll(builtFixture(t), `"DBUpdatedAt":"2026-11-26T10:00:00Z",`, "")), nil
	}}
	report, err := scanner.ScanBuiltImage(context.Background(), builtInput(), []string{builtRepository}, cfg)
	if err != nil || report.DatabaseUpdatedAt == nil || !report.DatabaseUpdatedAt.Equal(updated) {
		t.Fatalf("%+v %v", report, err)
	}
}
