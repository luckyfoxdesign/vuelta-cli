package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewAtRestrictsPathsAndWritesAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "vuelta.log")
	var stdout bytes.Buffer
	logger, err := NewAt(path, 1024, false, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Audit(AuditRecord{Project: "api", BaseSHA: "base", CommitSHA: "commit", AlertIDs: []string{"CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{filepath.Dir(path), path} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o700)
		if target == path {
			want = 0o600
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %04o, want %04o", target, info.Mode().Perm(), want)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "audit") || !strings.Contains(stdout.String(), "project=\"api\"") {
		t.Fatalf("log output = %q, err = %v", data, err)
	}
}

func TestLoggerRotatesBySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vuelta.log")
	logger, err := NewAt(path, 20, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Event("INFO", "first event", nil); err != nil {
		t.Fatal(err)
	}
	if err := logger.Event("INFO", "second event", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated log missing: %v", err)
	}
}

func TestLoggerRedactsSecretLikeFieldNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vuelta.log")
	logger, err := NewAt(path, 1024, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Event("ERROR", "delivery failed", map[string]string{"webhook_url": "https://example/secret", "bot_token": "token"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "https://example/secret") || strings.Contains(string(data), "token\"") {
		t.Fatalf("secret value leaked into log: %s", data)
	}
}
