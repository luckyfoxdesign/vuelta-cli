package main

import (
	"os"
	"path/filepath"
	"testing"
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
