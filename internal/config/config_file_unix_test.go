//go:build darwin || linux

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsUnsafeConfigMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	const secret = "fake-inline-secret-must-not-appear"
	if err := os.WriteFile(path, []byte("workspaces: []\n# "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load secure config: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("Load mode 0644 error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe config error leaked file contents: %v", err)
	}
}

func TestLoadRejectsConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	link := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(target, []byte("workspaces: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := Load(link)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Load symlink error = %v", err)
	}
}

func TestValidateConfigFileRejectsDifferentOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("workspaces: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongUID := uint32(os.Geteuid()) + 1
	if err := validateConfigFile(path, info, wrongUID); err == nil || !strings.Contains(err.Error(), "owned by the current process uid") {
		t.Fatalf("owner mismatch error = %v", err)
	}
}
