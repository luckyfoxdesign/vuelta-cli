package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestConfigInitNonInteractive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := run([]string{"config", "init", "--no-input", "--config", path})
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
	if len(cfg.Workspaces) != 0 {
		t.Fatalf("config init created %d workspaces, want none", len(cfg.Workspaces))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", info.Mode().Perm())
	}
	if err := run([]string{"--config", path, "config", "init", "--no-input"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second config init error = %v, want no-overwrite error", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("# replacement review\n"), contents...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config", path, "config", "init", "--replace", "--no-input"}); err == nil || !strings.Contains(err.Error(), "--replace --yes") {
		t.Fatalf("unconfirmed replacement error = %v", err)
	}
	if err := run([]string{"--config", path, "config", "init", "--replace", "--yes", "--no-input"}); err != nil {
		t.Fatalf("confirmed replacement: %v", err)
	}
	if err := run([]string{"--config", path, "config", "init", "--force"}); err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("removed --force error = %v", err)
	}
}

func TestProjectAddNonInteractiveReportsMissingValue(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := run([]string{"config", "init", "--config", configPath}); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "compose.yml"), []byte("services:\n  test: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"project", "add", "--no-input", "--yes", "--config", configPath, project})
	if err == nil || !strings.Contains(err.Error(), "--stack is required") {
		t.Fatalf("project add error = %v, want missing stack error", err)
	}
}

func TestProjectAddNonInteractiveIsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := run([]string{"config", "init", "--config", configPath}); err != nil {
		t.Fatal(err)
	}
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
	args := []string{"project", "add", project, "--name", "api", "--branch", "main", "--remote", "origin", "--yes", "--no-input", "--config", configPath}
	if err := run(args); err != nil {
		t.Fatalf("project add: %v", err)
	}
	if err := run(args); err != nil {
		t.Fatalf("idempotent project add: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Workspaces) != 1 || cfg.Workspaces[0].Name != "api" || cfg.Workspaces[0].Path != project {
		t.Fatalf("workspaces = %#v", cfg.Workspaces)
	}
}

func TestProjectListAndConfigValidateJSONEnvelopes(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := run([]string{"config", "init", "--config", configPath}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		args    []string
		command string
		wantErr bool
	}{
		{name: "project list success", args: []string{"project", "list", "--json", "--config", configPath}, command: "project list"},
		{name: "config validate success", args: []string{"config", "validate", "--json", "--config", configPath}, command: "config validate"},
		{name: "config validate failure", args: []string{"config", "validate", "--json", "--config", filepath.Join(t.TempDir(), "missing.yaml")}, command: "config validate", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, runErr := captureStdout(t, func() error { return run(test.args) })
			if (runErr != nil) != test.wantErr {
				t.Fatalf("run error = %v, wantErr %t", runErr, test.wantErr)
			}
			var envelope jsonCommandEnvelope
			if err := json.Unmarshal([]byte(output), &envelope); err != nil {
				t.Fatalf("invalid JSON %q: %v", output, err)
			}
			if envelope.Format != 1 || envelope.Command != test.command || envelope.Results == nil || envelope.Warnings == nil || envelope.Errors == nil {
				t.Fatalf("envelope = %#v", envelope)
			}
			if test.wantErr && len(envelope.Errors) != 1 {
				t.Fatalf("errors = %#v", envelope.Errors)
			}
		})
	}
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	runErr := fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = previous
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(output), runErr
}

func TestLocalPackageUpdateRejectsApplyAndDryRunTogether(t *testing.T) {
	err := run([]string{"package", "local", "update", "--policy", "local.yaml", "--apply", "--dry-run"})
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("local update error = %v, want conflicting confirmation flags", err)
	}
}
