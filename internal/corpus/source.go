package corpus

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
)

const (
	defaultCheckoutLimit = int64(50 << 20)
	archiveOutputLimit   = 64 << 20
	defaultFetchTimeout  = 2 * time.Minute
	largeProjectMinimum  = int64(5 << 20)
)

// PreparedSource is a fresh, disposable scan tree backed by an immutable
// URL/commit cache. Cleanup removes only this run's temporary tree.
type PreparedSource struct {
	Root       string
	ScanRoot   string
	BaseCommit string
	CacheHit   bool
	Cleanup    func() error
}

// SourcePreparer supplies fresh work copies to the runner.
type SourcePreparer interface {
	Prepare(context.Context, string, string, Case) (PreparedSource, error)
}

// SourceStore safely fetches exact GitHub commits and materializes only the
// allowlisted scan inputs and license marker. Secret-like paths are never
// extracted from the opaque Git object cache.
type SourceStore struct {
	Git           gitexec.Runner
	CheckoutLimit int64
	FetchTimeout  time.Duration
}

// Prepare ensures an immutable cache entry and creates one fresh work copy.
func (s SourceStore) Prepare(ctx context.Context, corpusRoot, tempRoot string, corpusCase Case) (PreparedSource, error) {
	if err := validateManagedRoot(corpusRoot); err != nil {
		return PreparedSource{}, err
	}
	if err := validateManagedRoot(tempRoot); err != nil {
		return PreparedSource{}, err
	}
	if err := corpusCase.validate(false); err != nil {
		return PreparedSource{}, err
	}
	runner := s.Git
	if runner == nil {
		runner = gitexec.Default()
	}
	cacheDir, cacheHit, err := s.ensureCache(ctx, runner, corpusRoot, corpusCase)
	if err != nil {
		return PreparedSource{}, err
	}
	if slicesContains(corpusCase.Features, "large-project") {
		size, err := boundedTreeSize(cacheDir, s.checkoutLimit())
		if err != nil {
			return PreparedSource{}, fmt.Errorf("verify large-project source size: %w", err)
		}
		if size < largeProjectMinimum {
			return PreparedSource{}, fmt.Errorf(
				"large-project source is %d bytes; minimum is %d",
				size,
				largeProjectMinimum,
			)
		}
	}
	workParent, err := os.MkdirTemp(tempRoot, "case-"+corpusCase.Name+"-")
	if err != nil {
		return PreparedSource{}, fmt.Errorf("create corpus work directory: %w", err)
	}
	cleanup := func() error {
		if !isStrictDescendant(tempRoot, workParent) {
			return errors.New("refuse to clean an unmanaged corpus work directory")
		}
		return os.RemoveAll(workParent)
	}
	fail := func(runErr error) (PreparedSource, error) {
		_ = cleanup()
		return PreparedSource{}, runErr
	}
	repository := filepath.Join(workParent, "repo")
	if err := os.Mkdir(repository, 0o700); err != nil {
		return fail(fmt.Errorf("create corpus repository: %w", err))
	}
	if _, err := runner.Run(ctx, gitexec.Request{Dir: repository, Args: []string{"init", "."}}); err != nil {
		return fail(fmt.Errorf("initialize fresh corpus repository: %w", err))
	}
	if _, err := runner.Run(ctx, gitexec.Request{Dir: repository, Args: []string{"remote", "add", "cache", cacheDir}}); err != nil {
		return fail(fmt.Errorf("attach immutable corpus cache: %w", err))
	}
	if _, err := runner.Run(ctx, gitexec.Request{
		Dir: repository, Args: []string{"fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "cache", corpusCase.Commit},
	}); err != nil {
		return fail(fmt.Errorf("fetch cached corpus commit: %w", err))
	}
	if err := verifyFetchedCommit(ctx, runner, repository, corpusCase.Commit); err != nil {
		return fail(err)
	}
	if _, err := runner.Run(ctx, gitexec.Request{Dir: repository, Args: []string{"read-tree", corpusCase.Commit}}); err != nil {
		return fail(fmt.Errorf("prepare corpus index: %w", err))
	}
	paths, licensePath, err := allowedArchivePaths(ctx, runner, repository, corpusCase)
	if err != nil {
		return fail(err)
	}
	if err := extractArchive(ctx, runner, repository, corpusCase.Commit, paths, s.checkoutLimit()); err != nil {
		return fail(err)
	}
	scanRoot := filepath.Join(repository, filepath.FromSlash(corpusCase.Subdir))
	if err := verifySourceMarkers(scanRoot, filepath.Join(repository, filepath.FromSlash(licensePath)), corpusCase); err != nil {
		return fail(err)
	}
	return PreparedSource{
		Root: repository, ScanRoot: scanRoot, BaseCommit: corpusCase.Commit,
		CacheHit: cacheHit, Cleanup: cleanup,
	}, nil
}

func (s SourceStore) ensureCache(ctx context.Context, runner gitexec.Runner, corpusRoot string, corpusCase Case) (string, bool, error) {
	cacheRoot := filepath.Join(corpusRoot, "cache")
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		return "", false, fmt.Errorf("create corpus cache: %w", err)
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(corpusCase.URL+"\n"+corpusCase.Commit)))
	finalDir := filepath.Join(cacheRoot, key)
	if info, err := os.Stat(finalDir); err == nil && info.IsDir() {
		if err := verifyTreeSize(finalDir, s.checkoutLimit()); err != nil {
			return "", false, fmt.Errorf("verify immutable corpus cache size: %w", err)
		}
		if err := verifyFetchedCommit(ctx, runner, finalDir, corpusCase.Commit); err != nil {
			return "", false, fmt.Errorf("verify immutable corpus cache: %w", err)
		}
		return finalDir, true, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", false, fmt.Errorf("inspect corpus cache: %w", err)
	}
	staging, err := os.MkdirTemp(cacheRoot, ".fetch-")
	if err != nil {
		return "", false, fmt.Errorf("create corpus cache staging directory: %w", err)
	}
	removeStaging := true
	defer func() {
		if removeStaging {
			_ = os.RemoveAll(staging)
		}
	}()
	fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout())
	defer cancel()
	if _, err := runner.Run(fetchCtx, gitexec.Request{Dir: staging, Args: []string{"init", "--bare", "."}}); err != nil {
		return "", false, fmt.Errorf("initialize corpus source cache: %w", err)
	}
	if _, err := runner.Run(fetchCtx, gitexec.Request{Dir: staging, Args: []string{"remote", "add", "origin", corpusCase.URL}}); err != nil {
		return "", false, fmt.Errorf("configure corpus source cache: %w", err)
	}
	if _, err := runner.Run(fetchCtx, gitexec.Request{
		Dir: staging, Args: []string{"fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "origin", corpusCase.Commit},
	}); err != nil {
		if errors.Is(fetchCtx.Err(), context.DeadlineExceeded) {
			return "", false, ErrTimeout
		}
		return "", false, fmt.Errorf("fetch exact corpus commit: %w", err)
	}
	if err := verifyFetchedCommit(fetchCtx, runner, staging, corpusCase.Commit); err != nil {
		return "", false, err
	}
	if err := verifyTreeSize(staging, s.checkoutLimit()); err != nil {
		return "", false, fmt.Errorf("verify fetched corpus size: %w", err)
	}
	if err := makeTreeReadOnly(staging); err != nil {
		return "", false, fmt.Errorf("protect immutable corpus cache: %w", err)
	}
	if err := os.Rename(staging, finalDir); err != nil {
		if info, statErr := os.Stat(finalDir); statErr == nil && info.IsDir() {
			return finalDir, true, nil
		}
		return "", false, fmt.Errorf("publish immutable corpus cache: %w", err)
	}
	removeStaging = false
	return finalDir, false, nil
}

func verifyFetchedCommit(ctx context.Context, runner gitexec.Runner, repository, want string) error {
	result, err := runner.Run(ctx, gitexec.Request{Dir: repository, Args: []string{"rev-parse", "FETCH_HEAD^{commit}"}})
	if err != nil {
		return fmt.Errorf("resolve fetched corpus commit: %w", err)
	}
	if strings.TrimSpace(string(result.Output)) != want {
		return errors.New("fetched corpus commit did not match the manifest pin")
	}
	return nil
}

func allowedArchivePaths(ctx context.Context, runner gitexec.Runner, repository string, corpusCase Case) ([]string, string, error) {
	result, err := runner.Run(ctx, gitexec.Request{
		Dir: repository, Args: []string{"ls-tree", "-r", "-z", "--full-tree", corpusCase.Commit},
	})
	if err != nil {
		return nil, "", fmt.Errorf("list corpus tree: %w", err)
	}
	treePaths, err := parseTreePaths(result.Output)
	if err != nil {
		return nil, "", err
	}
	prefix := ""
	if corpusCase.Subdir != "" {
		prefix = corpusCase.Subdir + "/"
	}
	required, optional, absent, err := sourcePathContractForCase(corpusCase)
	if err != nil {
		return nil, "", err
	}
	if absent != "" {
		lockPath := prefix + absent
		if treePaths[lockPath] {
			return nil, "", fmt.Errorf("manifest-without-lockfile case unexpectedly contains %s", lockPath)
		}
	}
	allowed := make(map[string]bool)
	for _, rel := range required {
		allowed[prefix+rel] = true
	}
	for _, rel := range optional {
		if treePaths[prefix+rel] {
			allowed[prefix+rel] = true
		}
	}
	if treePaths[prefix+".vuelta.yaml"] || hasPathPrefix(treePaths, prefix+".vuelta/") {
		return nil, "", errors.New("corpus source already contains Vuelta onboarding state")
	}
	licensePath := selectLicensePath(treePaths)
	if licensePath == "" {
		return nil, "", errors.New("corpus source does not contain an allowlisted license file")
	}
	allowed[licensePath] = true
	paths := make([]string, 0, len(allowed))
	for rel := range allowed {
		if !treePaths[rel] {
			if slicesContains(required, strings.TrimPrefix(rel, prefix)) {
				return nil, "", fmt.Errorf("corpus source is missing required marker %s", rel)
			}
			continue
		}
		if isSecretLikePath(rel) {
			return nil, "", fmt.Errorf("required corpus marker %s is secret-like and cannot be extracted", rel)
		}
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	return paths, licensePath, nil
}

func parseTreePaths(output []byte) (map[string]bool, error) {
	paths := make(map[string]bool)
	if len(output) == 0 {
		return paths, nil
	}
	if output[len(output)-1] != 0 {
		return nil, errors.New("git tree output was not NUL-terminated")
	}
	for _, entry := range bytes.Split(output[:len(output)-1], []byte{0}) {
		header, rel, ok := bytes.Cut(entry, []byte{'\t'})
		fields := bytes.Fields(header)
		if !ok || len(fields) != 3 || string(fields[1]) != "blob" {
			continue
		}
		value := string(rel)
		if !safeArchivePath(value) {
			return nil, errors.New("git tree contains an unsafe path")
		}
		paths[value] = true
	}
	return paths, nil
}

func sourcePathContract(manager string) ([]string, []string) {
	common := []string{".gitignore", "Dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
	switch manager {
	case "npm":
		return []string{"package.json", "package-lock.json"}, common
	case "pnpm":
		return []string{"package.json", "pnpm-lock.yaml"}, append(common, "pnpm-workspace.yaml")
	case "bun":
		return []string{"package.json", "bun.lock"}, common
	case "poetry":
		return []string{"pyproject.toml", "poetry.lock"}, common
	case "uv":
		return []string{"pyproject.toml", "uv.lock"}, common
	case "pip-tools":
		return []string{"requirements.in", "requirements.txt"}, common
	case "requirements":
		return []string{"requirements.txt"}, common
	default:
		return nil, common
	}
}

func sourcePathContractForCase(corpusCase Case) ([]string, []string, string, error) {
	required, optional := sourcePathContract(corpusCase.ExpectedPackageManager)
	if !slicesContains(corpusCase.Features, "dockerfile") &&
		!slicesContains(corpusCase.Features, "multi-stack-node") &&
		!slicesContains(corpusCase.Features, "multi-stack-python") {
		filtered := optional[:0]
		for _, path := range optional {
			switch path {
			case "Dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml":
			default:
				filtered = append(filtered, path)
			}
		}
		optional = filtered
	}
	if !slicesContains(corpusCase.Features, "manifest-without-lockfile") {
		return required, optional, "", nil
	}
	if len(required) < 2 {
		return nil, nil, "", errors.New("manifest-without-lockfile requires a manager with distinct manifest and lock markers")
	}
	absent := required[len(required)-1]
	return required[:len(required)-1], optional, absent, nil
}

func selectLicensePath(paths map[string]bool) string {
	names := []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt",
		"LICENCE", "LICENCE.txt", "LICENCE.md",
		"license", "license.txt", "license.md",
	}
	for _, name := range names {
		if paths[name] {
			return name
		}
	}
	return ""
}

func extractArchive(ctx context.Context, runner gitexec.Runner, repository, commit string, paths []string, checkoutLimit int64) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	collector := capio.NewLimit(archiveOutputLimit, cancel)
	args := append([]string{"archive", "--format=tar", commit, "--"}, paths...)
	_, err := runner.Run(runCtx, gitexec.Request{Dir: repository, Args: args, Stdout: collector})
	if collector.Exceeded() {
		return errors.New("corpus archive exceeded its bounded transfer limit")
	}
	if err != nil {
		return fmt.Errorf("archive allowlisted corpus inputs: %w", err)
	}
	reader := tar.NewReader(bytes.NewReader(collector.Bytes()))
	var extracted int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read corpus archive: %w", nextErr)
		}
		archiveName := normalizedArchiveEntryName(header.Name, header.Typeflag)
		if !safeArchivePath(archiveName) || isSecretLikePath(archiveName) {
			return errors.New("corpus archive contained an unsafe path")
		}
		target := filepath.Join(repository, filepath.FromSlash(archiveName))
		if !isStrictDescendant(repository, target) {
			return errors.New("corpus archive escaped the work directory")
		}
		switch header.Typeflag {
		case tar.TypeXGlobalHeader:
			// git archive emits a bounded PAX global header containing commit
			// metadata before the allowlisted entries.
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("create corpus source directory: %w", err)
			}
		case tar.TypeReg:
			extracted += header.Size
			if extracted > checkoutLimit {
				return fmt.Errorf("corpus checkout exceeds %d bytes", checkoutLimit)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("create corpus source parent: %w", err)
			}
			file, openErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if openErr != nil {
				return fmt.Errorf("create corpus source file: %w", openErr)
			}
			_, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("extract corpus source file: %w", copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close corpus source file: %w", closeErr)
			}
		case tar.TypeSymlink:
			return errors.New("corpus archive contains a symbolic link")
		default:
			return fmt.Errorf("corpus archive contains unsupported entry type %d", header.Typeflag)
		}
	}
	return nil
}

func normalizedArchiveEntryName(name string, typeflag byte) string {
	if typeflag == tar.TypeDir {
		return strings.TrimSuffix(name, "/")
	}
	return name
}

func verifySourceMarkers(scanRoot, licensePath string, corpusCase Case) error {
	if info, err := os.Stat(scanRoot); err != nil || !info.IsDir() {
		return errors.New("corpus subdir is not a directory")
	}
	required, _, _, err := sourcePathContractForCase(corpusCase)
	if err != nil {
		return err
	}
	for _, rel := range required {
		info, statErr := os.Lstat(filepath.Join(scanRoot, rel))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("corpus marker %s is unavailable or unsafe", rel)
		}
	}
	info, err := os.Lstat(licensePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 128<<10 {
		return errors.New("corpus license file is unavailable, unsafe, or oversized")
	}
	content, err := os.ReadFile(licensePath)
	if err != nil {
		return fmt.Errorf("read allowlisted corpus license: %w", err)
	}
	if !matchesLicenseText(string(content), corpusCase.License) {
		return fmt.Errorf("corpus license text does not match declared %s", corpusCase.License)
	}
	if err := verifyLockFormatMarker(scanRoot, corpusCase); err != nil {
		return err
	}
	if err := verifyFeatureMarkers(scanRoot, corpusCase); err != nil {
		return err
	}
	return nil
}

func verifyLockFormatMarker(scanRoot string, corpusCase Case) error {
	read := func(name string) ([]byte, error) {
		filename := filepath.Join(scanRoot, name)
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 16<<20 {
			return nil, fmt.Errorf("lock format marker %s is unavailable, unsafe, or oversized", name)
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read allowlisted lock marker %s: %w", name, err)
		}
		return content, nil
	}
	switch corpusCase.ExpectedLockFormat {
	case "absent", "requirements", "requirements-direct", "bun-text":
		return nil
	case "npm-v2", "npm-v3":
		content, err := read("package-lock.json")
		if err != nil {
			return err
		}
		var marker struct {
			LockfileVersion int `json:"lockfileVersion"`
		}
		if err := json.Unmarshal(content, &marker); err != nil {
			return errors.New("package-lock.json is not valid JSON")
		}
		want := 2
		if corpusCase.ExpectedLockFormat == "npm-v3" {
			want = 3
		}
		if marker.LockfileVersion != want {
			return fmt.Errorf("expected npm lockfileVersion %d, observed %d", want, marker.LockfileVersion)
		}
	case "pnpm-v9":
		content, err := read("pnpm-lock.yaml")
		if err != nil {
			return err
		}
		text := string(content)
		if !strings.Contains(text, "lockfileVersion: '9.") &&
			!strings.Contains(text, `lockfileVersion: "9.`) &&
			!strings.Contains(text, "lockfileVersion: 9.") {
			return errors.New("pnpm lockfile does not declare schema version 9")
		}
	case "poetry-v2":
		content, err := read("poetry.lock")
		if err != nil {
			return err
		}
		if !strings.Contains(string(content), `lock-version = "2.`) {
			return errors.New("poetry lockfile does not declare schema version 2")
		}
	case "uv-v1":
		content, err := read("uv.lock")
		if err != nil {
			return err
		}
		if !strings.Contains(string(content), "version = 1") {
			return errors.New("uv lockfile does not declare schema version 1")
		}
	default:
		if !slicesContains(corpusCase.Features, "discovery") {
			return fmt.Errorf("lock format %q has no source verification contract", corpusCase.ExpectedLockFormat)
		}
	}
	return nil
}

func verifyFeatureMarkers(scanRoot string, corpusCase Case) error {
	if slicesContains(corpusCase.Features, "nested-root") && corpusCase.Subdir == "" {
		return errors.New("nested-root feature requires a non-empty subdir")
	}
	if slicesContains(corpusCase.Features, "dockerfile") {
		if err := verifyRegularBoundedFile(filepath.Join(scanRoot, "Dockerfile"), 1<<20); err != nil {
			return fmt.Errorf("dockerfile feature: %w", err)
		}
	}
	orderedRequirementFeatures := []string{
		"requirements-include-directive",
		"requirements-constraint-directive",
		"requirements-hashes",
		"requirements-url-dependency",
	}
	requirementFeatures := make(map[string]bool, len(orderedRequirementFeatures))
	needed := false
	for _, feature := range orderedRequirementFeatures {
		if slicesContains(corpusCase.Features, feature) {
			needed = true
		}
	}
	if !needed {
		return nil
	}
	var marker bytes.Buffer
	for _, name := range []string{"requirements.in", "requirements.txt"} {
		filename := filepath.Join(scanRoot, name)
		info, err := os.Lstat(filename)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
			return fmt.Errorf("requirements feature marker %s is unavailable, unsafe, or oversized", name)
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read allowlisted requirements marker %s: %w", name, err)
		}
		marker.Write(content)
		marker.WriteByte('\n')
	}
	for _, raw := range strings.Split(marker.String(), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case requirementDirective(line, "-r", "--requirement"):
			requirementFeatures["requirements-include-directive"] = true
		case requirementDirective(line, "-c", "--constraint"):
			requirementFeatures["requirements-constraint-directive"] = true
		}
		if strings.Contains(line, "--hash=") {
			requirementFeatures["requirements-hashes"] = true
		}
		if requirementURLDependency(line) {
			requirementFeatures["requirements-url-dependency"] = true
		}
	}
	for _, feature := range orderedRequirementFeatures {
		if slicesContains(corpusCase.Features, feature) && !requirementFeatures[feature] {
			return fmt.Errorf("declared feature %s is absent from requirements markers", feature)
		}
	}
	return nil
}

func requirementDirective(line, short, long string) bool {
	return line == short || strings.HasPrefix(line, short+" ") || strings.HasPrefix(line, short+"=") ||
		line == long || strings.HasPrefix(line, long+" ") || strings.HasPrefix(line, long+"=")
}

func requirementURLDependency(line string) bool {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "-e ") || strings.HasPrefix(lower, "--editable ") {
		return strings.Contains(lower, "://")
	}
	return !strings.HasPrefix(lower, "-") && strings.Contains(lower, "://")
}

func verifyRegularBoundedFile(filename string, limit int64) error {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return errors.New("marker is unavailable, unsafe, or oversized")
	}
	return nil
}

func matchesLicenseText(content, license string) bool {
	content = strings.ToLower(content)
	switch license {
	case "MIT":
		return strings.Contains(content, "permission is hereby granted, free of charge")
	case "Apache-2.0":
		return strings.Contains(content, "apache license") && strings.Contains(content, "version 2.0")
	case "ISC":
		return strings.Contains(content, "permission to use, copy, modify, and/or distribute")
	case "BSD-2-Clause", "BSD-3-Clause":
		return strings.Contains(content, "redistribution and use in source and binary forms")
	default:
		return false
	}
}

func safeArchivePath(value string) bool {
	return value != "" && filepath.ToSlash(filepath.Clean(value)) == value &&
		value != "." && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") &&
		!strings.Contains(value, "/../") && !strings.ContainsAny(value, "\x00\\\r\n")
}

func isSecretLikePath(value string) bool {
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(value)), "/") {
		switch {
		case part == ".ssh", part == ".aws", part == ".kube", part == ".gnupg",
			part == ".netrc", part == ".npmrc", part == "id_rsa", part == "id_ed25519",
			strings.HasPrefix(part, "id_rsa"), strings.HasPrefix(part, "id_ed25519"),
			strings.HasSuffix(part, ".pem"), strings.HasSuffix(part, ".key"),
			part == ".env", strings.HasPrefix(part, ".env."):
			return true
		}
	}
	return false
}

func hasPathPrefix(paths map[string]bool, prefix string) bool {
	for value := range paths {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func makeTreeReadOnly(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o500)
		}
		return os.Chmod(path, 0o400)
	})
}

func verifyTreeSize(root string, limit int64) error {
	_, err := boundedTreeSize(root, limit)
	return err
}

func boundedTreeSize(root string, limit int64) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > limit {
			return fmt.Errorf("tree exceeds %d bytes", limit)
		}
		return nil
	})
	return total, err
}

func validateManagedRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return errors.New("corpus root must be a normalized absolute non-root path")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return errors.New("corpus root must be an existing directory")
	}
	return nil
}

func isStrictDescendant(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != "." && relative != "" && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (s SourceStore) checkoutLimit() int64 {
	if s.CheckoutLimit > 0 {
		return s.CheckoutLimit
	}
	return defaultCheckoutLimit
}

func (s SourceStore) fetchTimeout() time.Duration {
	if s.FetchTimeout > 0 {
		return s.FetchTimeout
	}
	return defaultFetchTimeout
}

// SourceSnapshot is a bounded digest map used to reject scanner mutations
// outside the exact onboarding/private-state allowlist.
type SourceSnapshot map[string][32]byte

// SnapshotSource hashes regular, non-secret files while skipping .git and
// Vuelta's private state. The extracted source itself is capped at 50 MiB.
func SnapshotSource(root string) (SourceSnapshot, error) {
	snapshot := make(SourceSnapshot)
	var total int64
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if entry.IsDir() && (relative == ".git" || entry.Name() == ".vuelta") {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		if isSecretLikePath(relative) {
			return errors.New("secret-like path appeared in corpus work tree")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(filename)
			if err != nil {
				return err
			}
			snapshot[relative] = sha256.Sum256([]byte("symlink\x00" + target))
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("corpus work tree contains an unsupported file")
		}
		total += info.Size()
		if total > defaultCheckoutLimit {
			return errors.New("corpus work tree exceeds the source snapshot limit")
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		snapshot[relative] = sha256.Sum256(content)
		return nil
	})
	return snapshot, err
}

// CompareSource allows only .vuelta.yaml, the exact /.vuelta/ ignore rule,
// and private .vuelta/ state; any manifest, lock, or source mutation fails.
func CompareSource(root, scanRoot string, before, after SourceSnapshot) (onboarding, unexpected []string, err error) {
	scanRelative, err := filepath.Rel(root, scanRoot)
	if err != nil || scanRelative == ".." || strings.HasPrefix(scanRelative, ".."+string(filepath.Separator)) {
		return nil, nil, errors.New("scan root is outside the corpus work tree")
	}
	scanRelative = filepath.ToSlash(scanRelative)
	prefix := ""
	if scanRelative != "." {
		prefix = scanRelative + "/"
	}
	keys := make(map[string]bool, len(before)+len(after))
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		if before[key] == after[key] {
			continue
		}
		switch key {
		case prefix + ".vuelta.yaml":
			onboarding = append(onboarding, key)
		case prefix + ".gitignore":
			ok, checkErr := exactIgnoreRuleAdded(scanRoot, before[key])
			if checkErr != nil {
				return nil, nil, checkErr
			}
			if ok {
				onboarding = append(onboarding, key)
			} else {
				unexpected = append(unexpected, key)
			}
		default:
			unexpected = append(unexpected, key)
		}
	}
	return onboarding, unexpected, nil
}

func exactIgnoreRuleAdded(root string, beforeHash [32]byte) (bool, error) {
	after, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return false, err
	}
	lines := strings.Split(strings.ReplaceAll(string(after), "\r\n", "\n"), "\n")
	count := 0
	for _, line := range lines {
		if line == "/.vuelta/" {
			count++
		}
	}
	if count != 1 {
		return false, nil
	}
	for i, line := range lines {
		if line == "/.vuelta/" {
			without := append([]string(nil), lines[:i]...)
			without = append(without, lines[i+1:]...)
			candidate := strings.Join(without, "\n")
			if beforeHash == ([32]byte{}) && candidate == "" {
				return true, nil
			}
			if sha256.Sum256([]byte(candidate)) == beforeHash ||
				sha256.Sum256([]byte(strings.TrimSuffix(candidate, "\n"))) == beforeHash ||
				sha256.Sum256([]byte(candidate+"\n")) == beforeHash {
				return true, nil
			}
		}
	}
	return false, nil
}
