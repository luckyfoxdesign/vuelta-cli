package corpus

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
)

func TestSecretLikePath(t *testing.T) {
	t.Parallel()
	for _, value := range []string{".env", "nested/.env.local", ".npmrc", "id_ed25519", "cert.pem", ".ssh/config"} {
		if !isSecretLikePath(value) {
			t.Errorf("isSecretLikePath(%q) = false", value)
		}
	}
	for _, value := range []string{"package.json", "requirements.txt", "LICENSE", ".gitignore"} {
		if isSecretLikePath(value) {
			t.Errorf("isSecretLikePath(%q) = true", value)
		}
	}
}

func TestParseTreePathsRejectsTraversal(t *testing.T) {
	t.Parallel()
	valid := []byte("100644 blob 0123456789012345678901234567890123456789\tpackage.json\x00")
	paths, err := parseTreePaths(valid)
	if err != nil || !paths["package.json"] {
		t.Fatalf("parseTreePaths() = %#v, %v", paths, err)
	}
	unsafe := []byte("100644 blob 0123456789012345678901234567890123456789\t../escape\x00")
	if _, err := parseTreePaths(unsafe); err == nil {
		t.Fatal("parseTreePaths() accepted traversal")
	}
}

func TestSelectLicensePathAcceptsBritishSpelling(t *testing.T) {
	t.Parallel()
	if got := selectLicensePath(map[string]bool{"LICENCE.txt": true}); got != "LICENCE.txt" {
		t.Fatalf("selectLicensePath() = %q, want LICENCE.txt", got)
	}
}

func TestNormalizedArchiveEntryNameRemovesDirectorySlash(t *testing.T) {
	t.Parallel()
	if got := normalizedArchiveEntryName("nested/", tar.TypeDir); got != "nested" {
		t.Fatalf("normalizedArchiveEntryName() = %q, want nested", got)
	}
	if got := normalizedArchiveEntryName("nested/file", tar.TypeReg); got != "nested/file" {
		t.Fatalf("normalizedArchiveEntryName() changed regular file to %q", got)
	}
}

func TestVerifyFeatureMarkersRequirementsContracts(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	content := "-r requirements/base.txt\n-c constraints.txt\n" +
		"demo @ https://example.invalid/demo.whl --hash=sha256:abc\n"
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	corpusCase := testCase("requirements-features")
	corpusCase.Features = []string{
		"requirements-include-directive",
		"requirements-constraint-directive",
		"requirements-hashes",
		"requirements-url-dependency",
	}
	if err := verifyFeatureMarkers(root, corpusCase); err != nil {
		t.Fatalf("verifyFeatureMarkers() error = %v", err)
	}
	corpusCase.Features = []string{"dockerfile"}
	if err := verifyFeatureMarkers(root, corpusCase); err == nil {
		t.Fatal("verifyFeatureMarkers() accepted a missing declared Dockerfile")
	}
}

func TestVerifyLockFormatMarkerNPM(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "package-lock.json"),
		[]byte(`{"lockfileVersion":3}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	corpusCase := testCase("npm-lock")
	corpusCase.ExpectedLockFormat = "npm-v3"
	if err := verifyLockFormatMarker(root, corpusCase); err != nil {
		t.Fatalf("verifyLockFormatMarker() error = %v", err)
	}
	corpusCase.ExpectedLockFormat = "npm-v2"
	if err := verifyLockFormatMarker(root, corpusCase); err == nil {
		t.Fatal("verifyLockFormatMarker() accepted the wrong npm schema")
	}
}

func TestVerifyTreeSize(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "marker"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTreeSize(root, 5); err != nil {
		t.Fatalf("verifyTreeSize() rejected exact limit: %v", err)
	}
	if err := verifyTreeSize(root, 4); err == nil {
		t.Fatal("verifyTreeSize() accepted an oversized tree")
	}
}

func TestSnapshotAndCompareSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("node_modules/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := SnapshotSource(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".vuelta.yaml"), []byte("schema_version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("node_modules/\n/.vuelta/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := SnapshotSource(root)
	if err != nil {
		t.Fatal(err)
	}
	onboarding, unexpected, err := CompareSource(root, root, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(onboarding) != 2 || len(unexpected) != 0 {
		t.Fatalf("CompareSource() = onboarding %#v, unexpected %#v", onboarding, unexpected)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"changed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := SnapshotSource(root)
	if err != nil {
		t.Fatal(err)
	}
	_, unexpected, err = CompareSource(root, root, before, changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(unexpected) != 1 || unexpected[0] != "package.json" {
		t.Fatalf("unexpected changes = %#v", unexpected)
	}
}

func TestExactIgnoreRuleRejectsOtherMutation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	original := []byte("node_modules/\n")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), append(original, []byte("other/\n/.vuelta/\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := exactIgnoreRuleAdded(root, sha256.Sum256(original))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("exactIgnoreRuleAdded() accepted unrelated mutation")
	}
}

func TestCacheKeyDependsOnURLAndCommit(t *testing.T) {
	t.Parallel()
	first := sha256.Sum256([]byte("https://github.com/a/b\n" + "a"))
	second := sha256.Sum256([]byte("https://github.com/a/b\n" + "b"))
	if first == second {
		t.Fatal("cache key collision")
	}
}

type fakeGitRunner struct {
	mu          sync.Mutex
	originFetch int
	treePaths   []string
}

func (f *fakeGitRunner) Path() (string, error) { return "/usr/bin/git", nil }

func (f *fakeGitRunner) Run(_ context.Context, request gitexec.Request) (gitexec.Result, error) {
	if len(request.Args) == 0 {
		return gitexec.Result{}, fmt.Errorf("missing command")
	}
	switch request.Args[0] {
	case "fetch":
		for _, argument := range request.Args {
			if argument == "origin" {
				f.mu.Lock()
				f.originFetch++
				f.mu.Unlock()
			}
		}
	case "rev-parse":
		return gitexec.Result{Output: []byte(strings.Repeat("a", 40) + "\n")}, nil
	case "ls-tree":
		var output bytes.Buffer
		paths := f.treePaths
		if len(paths) == 0 {
			paths = []string{"LICENSE", "package-lock.json", "package.json"}
		}
		for index, path := range paths {
			fmt.Fprintf(&output, "100644 blob %040d\t%s%c", index+1, path, byte(0))
		}
		return gitexec.Result{Output: output.Bytes()}, nil
	case "archive":
		if request.Stdout == nil {
			return gitexec.Result{}, fmt.Errorf("archive did not stream")
		}
		writer := tar.NewWriter(request.Stdout)
		files := map[string]string{
			"LICENSE":           "Permission is hereby granted, free of charge, to any person obtaining a copy",
			"package-lock.json": `{"lockfileVersion":3}`,
			"package.json":      `{}`,
		}
		pathArguments := false
		for _, name := range request.Args {
			if name == "--" {
				pathArguments = true
				continue
			}
			if !pathArguments {
				continue
			}
			content := files[name]
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
				return gitexec.Result{}, err
			}
			if _, err := io.WriteString(writer, content); err != nil {
				return gitexec.Result{}, err
			}
		}
		if err := writer.Close(); err != nil {
			return gitexec.Result{}, err
		}
	}
	return gitexec.Result{}, nil
}

func TestManifestWithoutLockfileContract(t *testing.T) {
	t.Parallel()
	corpusCase := testCase("without-lock")
	corpusCase.Features = append(corpusCase.Features, "manifest-without-lockfile")
	corpusCase.ExpectedLockFormat = "absent"

	store := SourceStore{Git: &fakeGitRunner{treePaths: []string{"LICENSE", "package.json"}}}
	source, err := store.Prepare(context.Background(), t.TempDir(), t.TempDir(), corpusCase)
	if err != nil {
		t.Fatalf("Prepare() rejected manifest-only source: %v", err)
	}
	if err := source.Cleanup(); err != nil {
		t.Fatal(err)
	}

	store = SourceStore{Git: &fakeGitRunner{}}
	if _, err := store.Prepare(context.Background(), t.TempDir(), t.TempDir(), corpusCase); err == nil {
		t.Fatal("Prepare() accepted a manifest-without-lockfile case that contained a lockfile")
	}
}

func TestSourceStoreCacheHitStillCreatesFreshWorkCopy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	temp := t.TempDir()
	fake := &fakeGitRunner{}
	store := SourceStore{Git: fake}
	corpusCase := testCase("cached-case")
	first, err := store.Prepare(context.Background(), root, temp, corpusCase)
	if err != nil {
		t.Fatal(err)
	}
	if first.CacheHit {
		t.Fatal("first prepare unexpectedly hit cache")
	}
	firstRoot := first.Root
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	second, err := store.Prepare(context.Background(), root, temp, corpusCase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Cleanup() }()
	if !second.CacheHit {
		t.Fatal("second prepare did not hit immutable cache")
	}
	if second.Root == firstRoot {
		t.Fatal("cache hit reused the previous work copy")
	}
	fake.mu.Lock()
	originFetches := fake.originFetch
	fake.mu.Unlock()
	if originFetches != 1 {
		t.Fatalf("origin fetches = %d, want 1", originFetches)
	}
	entries, err := os.ReadDir(filepath.Join(root, "cache"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("immutable cache = %d entries, error %v", len(entries), err)
	}
}
