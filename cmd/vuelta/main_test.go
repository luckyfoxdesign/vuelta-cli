package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestConfigInitNonInteractive(t *testing.T) {
	project := t.TempDir()
	for name, contents := range map[string]string{
		"package.json":      "{}\n",
		"package-lock.json": "{}\n",
		"compose.yml":       "services:\n  test: {}\n",
	} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := run([]string{"config", "init", "--non-interactive", "--branch", "main", "--remote", "origin", project, path})
	if err != nil {
		t.Fatalf("config init: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load generated config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("generated config validation: %v", err)
	}
	if err := run([]string{"config", "init", "--non-interactive", "--branch", "main", "--remote", "origin", project, path}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second config init error = %v, want no-overwrite error", err)
	}
}

func TestConfigInitNonInteractiveReportsMissingValue(t *testing.T) {
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "compose.yml"), []byte("services:\n  test: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"config", "init", "--non-interactive", project, filepath.Join(t.TempDir(), "config.yaml")})
	if err == nil || !strings.Contains(err.Error(), "--stack is required") {
		t.Fatalf("config init error = %v, want missing stack error", err)
	}
}

func TestLocalPackageUpdateRejectsApplyAndDryRunTogether(t *testing.T) {
	err := run([]string{"package", "local", "update", "--policy", "local.yaml", "--apply", "--dry-run"})
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("local update error = %v, want conflicting confirmation flags", err)
	}
}
