package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/corpus"
)

func TestParseScanOptionsRootBeforeFlags(t *testing.T) {
	t.Parallel()
	options, err := parseScanOptions([]string{"/tmp/corpus", "--case", "example"})
	if err != nil {
		t.Fatal(err)
	}
	if options.root != "/tmp/corpus" || options.caseName != "example" {
		t.Fatalf("options = %#v", options)
	}
	if options.caseTimeout != corpus.DefaultCaseTimeout {
		t.Fatalf("case timeout = %s, want %s", options.caseTimeout, corpus.DefaultCaseTimeout)
	}
}

func TestParseScanOptionsTimeout(t *testing.T) {
	t.Parallel()
	options, err := parseScanOptions([]string{
		"/tmp/corpus", "--case", "example", "--timeout", "10m",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.caseTimeout != 10*time.Minute {
		t.Fatalf("case timeout = %s, want 10m", options.caseTimeout)
	}
}

func TestParseScanOptionsRejectsInvalidTimeoutBeforeExecution(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/path/that/does/not/exist", "--timeout"},
		{"/path/that/does/not/exist", "--timeout", "soon"},
		{"/path/that/does/not/exist", "--timeout", "0"},
		{"/path/that/does/not/exist", "--timeout", "-1s"},
		{"/path/that/does/not/exist", "--timeout", "24h1s"},
		{"/path/that/does/not/exist", "--timeout", "1m", "--timeout", "2m"},
	} {
		if _, err := parseScanOptions(args); err == nil {
			t.Fatalf("parseScanOptions(%#v) accepted invalid timeout", args)
		}
	}
}

func TestParseScanOptionsRejectsConflicts(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"/tmp/corpus", "--case", "a", "--only-failed", "/tmp/report.json"},
		{"/tmp/corpus", "--stable-only", "--case", "a"},
		{"relative"},
	} {
		if _, err := parseScanOptions(args); err == nil {
			t.Fatalf("parseScanOptions(%#v) accepted invalid input", args)
		}
	}
}

func TestValidateRootResolvesSymlinks(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "corpus-link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := validateRoot(link, source); err == nil {
		t.Fatal("validateRoot() accepted a symlink resolving to the app source")
	}
}
