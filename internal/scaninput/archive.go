package scaninput

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
)

const (
	defaultMaxFiles      = 32
	defaultMaxFileBytes  = 8 << 20
	defaultMaxTotalBytes = 32 << 20
	defaultMaxDepth      = 8
	containerInputUID    = 65532
	containerInputGID    = 65532
)

// Limits bound validation and archive construction before Docker starts.
type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxDepth      int
}

// Options distinguishes registered tracked workspaces from explicit adhoc
// inputs, which have no Git metadata but retain every filesystem check.
type Options struct {
	RequireTracked bool
	Limits         Limits
}

// Entry records exactly what a stage receives without retaining contents.
type Entry struct {
	Stage    Stage    `json:"stage"`
	Category Category `json:"category"`
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
}

// Manifest binds the sorted stage/category/path/content list.
type Manifest struct {
	Entries     []Entry
	Hash        string
	InputHashes map[string]string
}

// Bundle is an in-memory tar stream intended for `docker cp -`. No repository
// contents are written to a host staging directory.
type Bundle struct {
	Archive  []byte
	Manifest Manifest
	contents map[string][]byte
}

// Content returns a copy of one already validated file for host-side parsers.
func (b Bundle) Content(path string) ([]byte, bool) {
	data, ok := b.contents[filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))]
	return append([]byte(nil), data...), ok
}

// Destroy overwrites retained input bytes after the stage finishes.
func (b *Bundle) Destroy() {
	if b == nil {
		return
	}
	clear(b.Archive)
	for path, data := range b.contents {
		clear(data)
		delete(b.contents, path)
	}
	b.Archive = nil
}

type collectedFile struct {
	entry Entry
	data  []byte
}

// Build validates one contract and constructs its deterministic in-memory
// archive. It performs no host filesystem writes.
func Build(ctx context.Context, sourceRoot, repositoryRoot string, options Options, contract Contract) (Bundle, error) {
	files, err := collect(ctx, sourceRoot, repositoryRoot, options, contract)
	if err != nil {
		return Bundle{}, err
	}
	manifest, err := makeManifest(files)
	if err != nil {
		return Bundle{}, err
	}
	archive, err := makeArchive(files)
	if err != nil {
		return Bundle{}, err
	}
	contents := make(map[string][]byte, len(files))
	for _, file := range files {
		contents[file.entry.Path] = append([]byte(nil), file.data...)
	}
	return Bundle{Archive: archive, Manifest: manifest, contents: contents}, nil
}

// Combine merges manifests from the exact stages used by one scan.
func Combine(manifests ...Manifest) (Manifest, error) {
	var files []collectedFile
	for _, manifest := range manifests {
		for _, entry := range manifest.Entries {
			files = append(files, collectedFile{entry: entry})
		}
	}
	return makeManifest(files)
}

func collect(ctx context.Context, sourceRoot, repositoryRoot string, options Options, contract Contract) ([]collectedFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limits := normalizedLimits(options.Limits)
	if len(contract.Files) > limits.MaxFiles {
		return nil, fmt.Errorf("scan input count exceeds limit of %d", limits.MaxFiles)
	}
	source, err := canonicalDirectory(sourceRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve scan input source: %w", err)
	}
	repository := source
	if repositoryRoot != "" {
		repository, err = canonicalDirectory(repositoryRoot)
		if err != nil {
			return nil, fmt.Errorf("resolve scan input repository: %w", err)
		}
	}
	rootInfo, err := os.Stat(source)
	if err != nil {
		return nil, fmt.Errorf("stat scan input source: %w", err)
	}
	files := make([]collectedFile, 0, len(contract.Files))
	seen := make(map[string]bool, len(contract.Files))
	var total int64
	for _, spec := range contract.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rel, err := validateRelativePath(spec)
		if err != nil {
			return nil, err
		}
		if seen[rel] {
			return nil, errors.New("scan input contract contains a duplicate path")
		}
		seen[rel] = true
		if strings.Count(rel, "/")+1 > limits.MaxDepth {
			return nil, fmt.Errorf("scan input depth exceeds limit of %d", limits.MaxDepth)
		}
		label := diagnosticLabel(spec, rel)
		full := filepath.Join(source, filepath.FromSlash(rel))
		info, err := os.Lstat(full)
		if errors.Is(err, os.ErrNotExist) && spec.Optional {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat allowlisted %s: %w", label, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("allowlisted %s is not a regular file", label)
		}
		if !sameOwner(rootInfo, info) {
			return nil, fmt.Errorf("allowlisted %s has an unexpected owner", label)
		}
		if hasMultipleLinks(info) {
			return nil, fmt.Errorf("allowlisted %s has multiple hard links", label)
		}
		canonical, err := filepath.EvalSymlinks(full)
		if err != nil || canonical != full || !contains(source, canonical) {
			return nil, fmt.Errorf("allowlisted %s is not canonically contained", label)
		}
		if options.RequireTracked {
			if err := requireTracked(ctx, repository, rel, label); err != nil {
				return nil, err
			}
		}
		if info.Size() > limits.MaxFileBytes {
			return nil, fmt.Errorf("allowlisted %s exceeds per-file size limit", label)
		}
		file, err := openNoFollow(full)
		if err != nil {
			return nil, fmt.Errorf("open allowlisted %s: %w", label, err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			_ = file.Close()
			return nil, fmt.Errorf("allowlisted %s changed during validation", label)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, limits.MaxFileBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("read allowlisted %s: %w", label, errors.Join(readErr, closeErr))
		}
		if int64(len(data)) > limits.MaxFileBytes {
			return nil, fmt.Errorf("allowlisted %s exceeds per-file size limit", label)
		}
		after, err := os.Lstat(full)
		if err != nil || !os.SameFile(info, after) || after.Size() != int64(len(data)) || after.ModTime() != info.ModTime() {
			return nil, fmt.Errorf("allowlisted %s changed while being read", label)
		}
		if spec.ReviewedManagerConfig {
			if err := validateManagerConfig(data); err != nil {
				return nil, err
			}
		}
		total += int64(len(data))
		if total > limits.MaxTotalBytes {
			return nil, errors.New("scan inputs exceed total size limit")
		}
		sum := sha256.Sum256(data)
		files = append(files, collectedFile{entry: Entry{
			Stage: contract.Stage, Category: spec.Category, Path: rel,
			SHA256: fmt.Sprintf("%x", sum), Size: int64(len(data)),
		}, data: data})
	}
	return files, nil
}

func makeArchive(files []collectedFile) ([]byte, error) {
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	directories := map[string]bool{"project/": true}
	for _, file := range files {
		parent := filepath.ToSlash(filepath.Dir(file.entry.Path))
		for parent != "." {
			directories["project/"+strings.TrimSuffix(parent, "/")+"/"] = true
			parent = filepath.ToSlash(filepath.Dir(parent))
		}
	}
	dirs := make([]string, 0, len(directories))
	for directory := range directories {
		dirs = append(dirs, directory)
	}
	sort.Strings(dirs)
	for _, directory := range dirs {
		if err := w.WriteHeader(&tar.Header{
			Name: directory, Mode: 0o555, Typeflag: tar.TypeDir, Uid: containerInputUID, Gid: containerInputGID,
		}); err != nil {
			return nil, fmt.Errorf("write scan input directory archive: %w", err)
		}
	}
	for _, file := range files {
		if err := w.WriteHeader(&tar.Header{
			Name: "project/" + file.entry.Path, Mode: 0o444, Size: int64(len(file.data)),
			Typeflag: tar.TypeReg, Uid: containerInputUID, Gid: containerInputGID,
		}); err != nil {
			return nil, fmt.Errorf("write scan input file archive: %w", err)
		}
		if _, err := w.Write(file.data); err != nil {
			return nil, fmt.Errorf("write scan input contents archive: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close scan input archive: %w", err)
	}
	return buffer.Bytes(), nil
}

func makeManifest(files []collectedFile) (Manifest, error) {
	entries := make([]Entry, 0, len(files))
	for _, file := range files {
		entries = append(entries, file.entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		left := string(entries[i].Stage) + "\x00" + entries[i].Path + "\x00" + string(entries[i].Category)
		right := string(entries[j].Stage) + "\x00" + entries[j].Path + "\x00" + string(entries[j].Category)
		return left < right
	})
	data, err := json.Marshal(entries)
	if err != nil {
		return Manifest{}, fmt.Errorf("encode scan input manifest: %w", err)
	}
	sum := sha256.Sum256(data)
	hashes := make(map[string]string)
	for _, entry := range entries {
		if existing, ok := hashes[entry.Path]; ok && existing != entry.SHA256 {
			return Manifest{}, errors.New("scan input changed between stage contracts")
		}
		hashes[entry.Path] = entry.SHA256
	}
	return Manifest{Entries: entries, Hash: fmt.Sprintf("%x", sum), InputHashes: hashes}, nil
}

func validateRelativePath(spec File) (string, error) {
	if spec.Path == "" || strings.Contains(spec.Path, "\\") || filepath.IsAbs(spec.Path) {
		return "", errors.New("scan input path is not repository-relative")
	}
	rel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(spec.Path)))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errors.New("scan input path escapes the repository")
	}
	if spec.ReviewedManagerConfig {
		if spec.Category != CategoryManagerConfig || !approvedManagerConfigName(rel) {
			return "", errors.New("invalid reviewed package-manager config contract")
		}
		return rel, nil
	}
	if secretLikeName(rel) {
		return "", errors.New("scan input contract contains a disallowed secret-like name")
	}
	return rel, nil
}

func approvedManagerConfigName(rel string) bool {
	for _, configs := range managerConfigs {
		for _, allowed := range configs {
			if rel == allowed {
				return true
			}
		}
	}
	return false
}

func secretLikeName(rel string) bool {
	for _, component := range strings.Split(strings.ToLower(rel), "/") {
		if strings.HasPrefix(component, ".env") || strings.HasPrefix(component, ".git") || component == ".vuelta" ||
			component == ".npmrc" || component == ".netrc" || component == "pip.conf" || component == "auth.json" ||
			component == "id_rsa" || component == "id_ed25519" || strings.HasSuffix(component, ".pem") ||
			strings.HasSuffix(component, ".key") || strings.Contains(component, "credential") ||
			strings.Contains(component, "password") || strings.Contains(component, "secret") || strings.Contains(component, "token") {
			return true
		}
	}
	return false
}

var credentialURL = regexp.MustCompile(`(?i)https?://[^/@:\s]+:[^/@\s]+@`)

func validateManagerConfig(data []byte) error {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return errors.New("reviewed package-manager config is not valid text")
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "${") || strings.Contains(lower, "bearer ") || strings.Contains(lower, "basic ") || credentialURL.MatchString(line) {
			return errors.New("reviewed package-manager config contains credential-bearing input")
		}
		key := lower
		if index := strings.IndexByte(key, '='); index >= 0 {
			key = strings.TrimSpace(key[:index])
		} else if index := strings.IndexByte(key, ':'); index >= 0 {
			key = strings.TrimSpace(key[:index])
		}
		for _, marker := range []string{"_auth", "auth-token", "authtoken", "password", "passwd", "username", "credential", "client-cert", "keyfile", "certfile", "token"} {
			if strings.Contains(key, marker) {
				return errors.New("reviewed package-manager config contains credential-bearing input")
			}
		}
		for _, field := range strings.Fields(line) {
			if parsed, err := url.Parse(strings.Trim(field, `"'`)); err == nil && parsed.IsAbs() && parsed.User != nil {
				return errors.New("reviewed package-manager config contains credential-bearing input")
			}
		}
	}
	return nil
}

func requireTracked(ctx context.Context, repository, rel, label string) error {
	if _, err := gitexec.Output(ctx, repository, "ls-files", "--error-unmatch", "--", rel); err != nil {
		return fmt.Errorf("allowlisted %s must be tracked", label)
	}
	ignored, err := gitexec.Output(ctx, repository, "ls-files", "--cached", "--ignored", "--exclude-standard", "--", rel)
	if err != nil {
		return fmt.Errorf("check ignored status for allowlisted %s: %w", label, err)
	}
	if len(strings.TrimSpace(string(ignored))) > 0 {
		return fmt.Errorf("allowlisted %s is ignored by repository policy", label)
	}
	return nil
}

func diagnosticLabel(spec File, rel string) string {
	if spec.ReviewedManagerConfig {
		return "package-manager config"
	}
	return "scan input " + rel
}

func normalizedLimits(limits Limits) Limits {
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = defaultMaxFiles
	}
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = defaultMaxFileBytes
	}
	if limits.MaxTotalBytes <= 0 {
		limits.MaxTotalBytes = defaultMaxTotalBytes
	}
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = defaultMaxDepth
	}
	return limits
}

func canonicalDirectory(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(canonical)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path is not a canonical directory")
	}
	return canonical, nil
}

func contains(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
