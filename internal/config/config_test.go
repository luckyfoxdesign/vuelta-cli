package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsAutofixToNoShellTools(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("workspaces: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Autofix.AllowedTools != "Read,Edit,Grep" || cfg.Autofix.MaxTurns != 10 || cfg.Autofix.ClaudeBin != "claude" {
		t.Fatalf("unexpected secure autofix defaults: %+v", cfg.Autofix)
	}
}

func TestValidateProductionWorkerRejectsUnsafeOrIncompleteAdapter(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid := &ProductionWorkerConfig{
		StateDir: "/var/lib/vuelta/state", SourceMode: "signed_queue_file", QueueFile: "/var/lib/vuelta/queue.jsonl", ManifestDir: "/var/lib/vuelta/manifests",
		CandidatePublicKey: key, ManifestPublicKey: key, MaxCandidateAgeMinutes: 60, OperationTimeoutSecond: 120,
		Projects: []ProductionProject{{Name: "api", ImageRepository: "registry.example/vuelta/api", ComposeFile: "/etc/vuelta/api.compose.yml", Service: "api", HealthURL: "https://api.example.com/healthz", SmokeURL: "https://api.example.com/smoke"}},
	}
	if errs := validateProductionWorker(valid); len(errs) != 0 {
		t.Fatalf("valid production worker errors = %v", errs)
	}
	valid.Projects[0].ImageRepository = "registry.example/vuelta/api:latest"
	valid.Projects[0].SmokeURL = "http://api.example.com/smoke"
	if errs := validateProductionWorker(valid); len(errs) == 0 {
		t.Fatal("expected unsafe production adapter to be rejected")
	}
}

func TestValidateRejectsUnsafeTestRunArgument(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Workspaces: []Workspace{{
		Path: dir, Stack: StackDocker,
		Test:         TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test", RunArgs: []string{"--privileged"}},
		DockerImages: &DockerImagesSpec{Files: []string{}, RuntimeImages: []string{"registry.example/test@sha256:" + strings.Repeat("a", 64)}},
	}}, Git: GitConfig{AllowedChangedPaths: []string{"package-lock.json"}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "run_args") {
		t.Fatalf("expected run_args rejection, got %v", err)
	}
}

func TestValidateSecurityConfigRequiresPinnedScannerImages(t *testing.T) {
	validDigest := "scanner@sha256:" + strings.Repeat("a", 64)
	cfg := Config{VulnScan: VulnScanConfig{
		Enabled: true, Tool: "trivy", Image: validDigest,
		FailOnSeverity: "HIGH", DatabaseMaxAgeHours: 24,
		ImageScan: ImageScanConfig{Enabled: true, Tool: "trivy", Image: validDigest},
	}}
	if errs := validateSecurityConfig(cfg); len(errs) != 0 {
		t.Fatalf("valid scanner config errors = %v", errs)
	}
	cfg.VulnScan.ImageScan.Image = "aquasec/trivy:latest"
	if errs := validateSecurityConfig(cfg); len(errs) == 0 || !strings.Contains(errs[0].Error(), "image") {
		t.Fatalf("expected unpinned scanner image rejection, got %v", errs)
	}
}
