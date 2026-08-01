package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeVerifyFixtureProject(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"scripts":{"build":"tsc"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return project
}

func TestProjectVerifyInitWritesComposeFile(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	if err := run([]string{"project", "verify", "init", "--directory", project}); err != nil {
		t.Fatalf("project verify init: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(project, "compose.verify.yml"))
	if err != nil {
		t.Fatalf("read generated compose.verify.yml: %v", err)
	}
	if !strings.Contains(string(data), "read_only: true") {
		t.Fatalf("generated compose is missing read_only: true:\n%s", data)
	}
}

func TestProjectVerifyInitNeverOverwrites(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string) (string, error) {
		return "sha256:" + strings.Repeat("1", 64), nil
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	existing := filepath.Join(project, "compose.verify.yml")
	if err := os.WriteFile(existing, []byte("hand-written"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"project", "verify", "init", "--directory", project})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already-exists error, got %v", err)
	}
	data, readErr := os.ReadFile(existing)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "hand-written" {
		t.Fatal("existing compose.verify.yml must be left untouched")
	}
}

func TestProjectVerifyInitDigestFailureLeavesNoFile(t *testing.T) {
	previous := resolveVerifyDigest
	resolveVerifyDigest = func(context.Context, string) (string, error) {
		return "", errors.New("registry unreachable")
	}
	t.Cleanup(func() { resolveVerifyDigest = previous })

	project := writeVerifyFixtureProject(t)
	err := run([]string{"project", "verify", "init", "--directory", project})
	if err == nil || !strings.Contains(err.Error(), "registry unreachable") {
		t.Fatalf("expected digest resolution error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(project, "compose.verify.yml")); !os.IsNotExist(statErr) {
		t.Fatal("compose.verify.yml must not exist after digest resolution failure")
	}
}
