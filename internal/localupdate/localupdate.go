// Package localupdate implements explicit adhoc host package-manager updates
// in a minimal private writable copy. It never calls Git or Docker, rejects
// changes outside the recognized manifest/lock pair, and is intentionally
// separate from the registered-workspace pipeline.
package localupdate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/localexec"
	"github.com/luckyfoxdesign/vuelta/internal/pipeline"
)

var (
	packageNamePattern    = regexp.MustCompile(`^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)
	packageVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!<>=~:,-]*$`)
)

// Candidate is a package-manager result safe for human or JSON output.
// Registry-controlled strings are stripped of terminal control characters.
type Candidate struct {
	Name    string `json:"name"`
	Current string `json:"current,omitempty"`
	Target  string `json:"target"`
}

// Project is the detected, root-only manifest/lock-file pair.
type Project struct {
	Root        string
	Manager     string
	Manifest    string
	Lock        string
	ConfigFiles []string
}

// ScanResult reports candidates and whether the configured minimum release
// age was actually enforced by the selected manager.
type ScanResult struct {
	Project        Project     `json:"-"`
	Candidates     []Candidate `json:"candidates"`
	ReleaseAgeUsed bool        `json:"release_age_used"`
	ChangedFiles   []string    `json:"changed_files,omitempty"`
}

// UpdateOptions carries the explicit opt-ins that weaken local-mode defaults.
type UpdateOptions struct {
	Apply              bool
	DryRun             bool
	AllowProjectConfig bool
	AllowScripts       bool
}

// CommandResult preserves a program exit status without converting expected
// non-zero status (notably `npm outdated`) into a Go error.
type CommandResult struct {
	Output   string
	ExitCode int
}

// Runner is injectable so all safety paths can be tested without invoking a
// host package manager.
type Runner func(context.Context, string, string, []string, []string) (CommandResult, error)

// Service owns host-process boundaries for local mode. Manager binaries are
// resolved before the target directory is touched and are never accepted from
// the target itself.
type Service struct {
	Run      Runner
	LookPath func(string) (string, error)
	LockPath func(string) (string, error)
}

// NewService returns a Service which uses only direct argv execution and a
// minimal child environment. It deliberately does not inherit credentials,
// proxy variables, NODE_OPTIONS, Python settings, or manager configuration.
func NewService() Service {
	return Service{Run: runCommand, LookPath: exec.LookPath, LockPath: defaultLockPath}
}

// Detect resolves exactly one supported manifest/lock pair in the explicitly
// supplied directory. It neither searches parents nor follows manifest or
// lock-file symlinks.
func Detect(path string) (Project, error) {
	root, err := filepath.Abs(path)
	if err != nil {
		return Project{}, fmt.Errorf("resolve local project path: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Project{}, fmt.Errorf("resolve canonical local project path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return Project{}, fmt.Errorf("stat local project path: %w", err)
	}
	if !info.IsDir() {
		return Project{}, errors.New("local project path must be a directory")
	}

	type definition struct {
		manager, manifest, lock string
		configs                 []string
	}
	definitions := []definition{
		{"npm", "package.json", "package-lock.json", []string{".npmrc"}},
		{"pnpm", "package.json", "pnpm-lock.yaml", []string{".npmrc", "pnpm-workspace.yaml"}},
		{"bun", "package.json", "bun.lock", []string{".npmrc", "bunfig.toml"}},
		{"poetry", "pyproject.toml", "poetry.lock", []string{"poetry.toml"}},
		{"uv", "pyproject.toml", "uv.lock", []string{}},
		{"pip-tools", "requirements.in", "requirements.txt", []string{"pip.conf"}},
	}
	var matches []Project
	for _, definition := range definitions {
		if regularFile(root, definition.manifest) && regularFile(root, definition.lock) {
			matches = append(matches, Project{Root: root, Manager: definition.manager, Manifest: definition.manifest, Lock: definition.lock, ConfigFiles: definition.configs})
		}
	}
	if len(matches) == 0 {
		return Project{}, errors.New("local project needs exactly one supported regular manifest/lock pair at its root")
	}
	if len(matches) != 1 {
		return Project{}, errors.New("local project has multiple supported manifest/lock pairs; select a project with one pair")
	}
	return matches[0], nil
}

func regularFile(root, name string) bool {
	info, err := os.Lstat(filepath.Join(root, name))
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

// Scan discovers candidates using a manager from the system PATH. It is
// read-only from Vuelta's perspective; project-level manager configuration is
// rejected unless the user has explicitly opted in through policy or a flag.
func (s Service) Scan(ctx context.Context, path string, policy config.LocalPackagePolicy, allowProjectConfig bool) (ScanResult, error) {
	project, err := Detect(path)
	if err != nil {
		return ScanResult{}, err
	}
	if err := rejectProjectConfig(project, allowProjectConfig || policy.AllowProjectConfig); err != nil {
		return ScanResult{}, err
	}
	binary, err := s.systemManager(project)
	if err != nil {
		return ScanResult{}, err
	}
	if project.Manager == "pip-tools" {
		// pip-tools owns the write path (`pip-compile`), while pip exposes the
		// read-only outdated listing. Require both system binaries and never use
		// a project virtualenv binary for either operation.
		binary, err = s.systemBinary(project.Root, "pip")
		if err != nil {
			return ScanResult{}, err
		}
	}
	args, ageUsed := scanArgs(project.Manager, policy.MinReleaseAgeDays, time.Now())
	result, err := s.run(ctx, binary, project.Root, args)
	if err != nil {
		return ScanResult{}, fmt.Errorf("run local %s scan: %w", project.Manager, err)
	}
	if result.ExitCode != 0 && result.ExitCode != 1 {
		return ScanResult{}, fmt.Errorf("local %s scan failed (exit %d): %s", project.Manager, result.ExitCode, safeText(result.Output))
	}
	candidates, err := parseCandidates(result.Output)
	if err != nil {
		return ScanResult{}, fmt.Errorf("parse local %s scan: %w", project.Manager, err)
	}
	return ScanResult{Project: project, Candidates: candidates, ReleaseAgeUsed: ageUsed}, nil
}

// Update re-scans, requires an exact allowlisted candidate selection, checks
// manifest/lock consistency before writing, and restores its private backup
// after a failed manager call or an allowlist violation. This is detection and
// recovery, not container isolation: child-process side effects outside the
// dependency files cannot be undone.
func (s Service) Update(ctx context.Context, path string, policy config.LocalPackagePolicy, selected []Candidate, options UpdateOptions) (ScanResult, error) {
	if err := policy.Validate(); err != nil {
		return ScanResult{}, err
	}
	if len(selected) == 0 {
		return ScanResult{}, errors.New("at least one --package NAME@VERSION is required")
	}
	if !options.Apply && !options.DryRun {
		return ScanResult{}, errors.New("local update requires --apply; use --dry-run to inspect without writing")
	}
	project, err := Detect(path)
	if err != nil {
		return ScanResult{}, err
	}
	if err := rejectProjectConfig(project, options.AllowProjectConfig || policy.AllowProjectConfig); err != nil {
		return ScanResult{}, err
	}
	lockPath, err := s.lockPath()(project.Root)
	if err != nil {
		return ScanResult{}, err
	}
	lock, err := pipeline.AcquireProcessLock(lockPath)
	if err != nil {
		return ScanResult{}, fmt.Errorf("lock local project: %w", err)
	}
	defer func() { _ = lock.Release() }() // a failed release cannot hide an update failure

	binary, err := s.systemManager(project)
	if err != nil {
		return ScanResult{}, err
	}
	var scan ScanResult
	changed, err := InPrivateCopy(project.Root, options.AllowProjectConfig || policy.AllowProjectConfig, options.Apply, func(copyProject Project) error {
		var scanErr error
		scan, scanErr = s.scanProject(ctx, copyProject, binary, policy)
		if scanErr != nil {
			return scanErr
		}
		if err := validateSelection(policy, scan.Candidates, selected); err != nil {
			return err
		}
		if err := s.verifyConsistent(ctx, binary, copyProject, options.AllowScripts); err != nil {
			return err
		}
		for _, candidate := range selected {
			args := updateArgs(copyProject.Manager, candidate, options.AllowScripts)
			result, runErr := s.run(ctx, binary, copyProject.Root, args)
			if runErr != nil {
				return fmt.Errorf("run local %s update for %s: %w", copyProject.Manager, candidate.Name, runErr)
			}
			if result.ExitCode != 0 {
				return fmt.Errorf("local %s update for %s failed (exit %d): %s", copyProject.Manager, candidate.Name, result.ExitCode, safeText(result.Output))
			}
		}
		return nil
	})
	if err != nil {
		return ScanResult{}, err
	}
	scan.Project = project
	scan.ChangedFiles = changed
	return scan, nil
}

func (s Service) scanProject(ctx context.Context, project Project, binary string, policy config.LocalPackagePolicy) (ScanResult, error) {
	scanBinary := binary
	var err error
	if project.Manager == "pip-tools" {
		scanBinary, err = s.systemBinary(project.Root, "pip")
		if err != nil {
			return ScanResult{}, err
		}
	}
	args, ageUsed := scanArgs(project.Manager, policy.MinReleaseAgeDays, time.Now())
	result, err := s.run(ctx, scanBinary, project.Root, args)
	if err != nil {
		return ScanResult{}, fmt.Errorf("run local %s scan: %w", project.Manager, err)
	}
	if result.ExitCode != 0 && result.ExitCode != 1 {
		return ScanResult{}, fmt.Errorf("local %s scan failed (exit %d): %s", project.Manager, result.ExitCode, safeText(result.Output))
	}
	candidates, err := parseCandidates(result.Output)
	if err != nil {
		return ScanResult{}, fmt.Errorf("parse local %s scan: %w", project.Manager, err)
	}
	return ScanResult{Project: project, Candidates: candidates, ReleaseAgeUsed: ageUsed}, nil
}

// InPrivateCopy runs one update operation against a minimal private copy that
// contains only the recognized dependency files and explicitly approved
// package-manager configuration. Only manifest and lock-file changes can be
// copied back to the host target.
func InPrivateCopy(path string, allowProjectConfig, apply bool, operation func(Project) error) ([]string, error) {
	project, err := Detect(path)
	if err != nil {
		return nil, err
	}
	if err := rejectProjectConfig(project, allowProjectConfig); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vuelta-adhoc-update-")
	if err != nil {
		return nil, fmt.Errorf("create private update copy: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict private update copy: %w", err)
	}
	files := []string{project.Manifest, project.Lock}
	if allowProjectConfig {
		for _, name := range project.ConfigFiles {
			if regularFile(project.Root, name) {
				files = append(files, name)
			}
		}
	}
	for _, name := range files {
		if err := copyRegularFile(project.Root, dir, name); err != nil {
			return nil, err
		}
	}
	copyProject := project
	copyProject.Root = dir
	before, err := privateProjectState(copyProject)
	if err != nil {
		return nil, err
	}
	if err := operation(copyProject); err != nil {
		return nil, err
	}
	after, err := privateProjectState(copyProject)
	if err != nil {
		return nil, err
	}
	if err := before.onlyAllowedChanges(after, copyProject); err != nil {
		return nil, fmt.Errorf("private update copy security check: %w", err)
	}
	changed := changedDependencyFiles(before, after, copyProject)
	if apply && len(changed) > 0 {
		if err := copyBackAtomically(project, copyProject, before, changed); err != nil {
			return nil, err
		}
	}
	return changed, nil
}

func privateProjectState(project Project) (state, error) {
	result, err := projectState(project)
	if err != nil {
		return nil, err
	}
	for name, item := range result {
		if !item.mode.IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(project.Root, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		item.digest = fmt.Sprintf("%x", sum)
		result[name] = item
	}
	return result, nil
}

func copyRegularFile(sourceRoot, destinationRoot, name string) error {
	info, err := os.Lstat(filepath.Join(sourceRoot, name))
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("copy dependency input %s: not a regular file", name)
	}
	data, err := os.ReadFile(filepath.Join(sourceRoot, name))
	if err != nil {
		return fmt.Errorf("read dependency input %s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(destinationRoot, name), data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write private dependency input %s: %w", name, err)
	}
	return nil
}

func changedDependencyFiles(before, after state, project Project) []string {
	var changed []string
	for _, name := range []string{project.Manifest, project.Lock} {
		if before[name] != after[name] {
			changed = append(changed, name)
		}
	}
	return changed
}

func copyBackAtomically(host, private Project, expected state, changed []string) error {
	hostState, err := projectState(host)
	if err != nil {
		return fmt.Errorf("revalidate host dependency inputs: %w", err)
	}
	for _, name := range []string{host.Manifest, host.Lock} {
		if hostState[name].digest != expected[name].digest || hostState[name].mode.Perm() != expected[name].mode.Perm() {
			return fmt.Errorf("host dependency input %s changed during private update", name)
		}
	}
	original := make(map[string][]byte, len(changed))
	modes := make(map[string]fs.FileMode, len(changed))
	for _, name := range changed {
		info, err := os.Lstat(filepath.Join(host.Root, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("copy back %s: host input is no longer a regular file", name)
		}
		data, err := os.ReadFile(filepath.Join(host.Root, name))
		if err != nil {
			return fmt.Errorf("read host input %s before copy back: %w", name, err)
		}
		original[name], modes[name] = data, info.Mode().Perm()
	}
	var replaced []string
	for _, name := range changed {
		data, err := os.ReadFile(filepath.Join(private.Root, name))
		if err == nil {
			err = atomicWrite(filepath.Join(host.Root, name), data, modes[name])
		}
		if err != nil {
			var restoreErrs []error
			for _, restore := range replaced {
				if restoreErr := atomicWrite(filepath.Join(host.Root, restore), original[restore], modes[restore]); restoreErr != nil {
					restoreErrs = append(restoreErrs, fmt.Errorf("restore %s: %w", restore, restoreErr))
				}
			}
			if restoreErr := errors.Join(restoreErrs...); restoreErr != nil {
				return fmt.Errorf("atomically copy back %s: %w; rollback incomplete: %v", name, err, restoreErr)
			}
			return fmt.Errorf("atomically copy back %s: %w", name, err)
		}
		replaced = append(replaced, name)
	}
	return nil
}

func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vuelta-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s Service) verifyConsistent(ctx context.Context, binary string, project Project, allowScripts bool) error {
	args := consistencyArgs(project.Manager, allowScripts)
	result, err := s.run(ctx, binary, project.Root, args)
	if err != nil {
		return fmt.Errorf("check manifest and lock consistency: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("manifest and lock are inconsistent; fix them before local update (exit %d): %s", result.ExitCode, safeText(result.Output))
	}
	return nil
}

func (s Service) systemManager(project Project) (string, error) {
	name := project.Manager
	if project.Manager == "pip-tools" {
		name = "pip-compile"
	}
	return s.systemBinary(project.Root, name)
}

func (s Service) systemBinary(root, name string) (string, error) {
	return localexec.Resolve(root, name, s.lookPath())
}

func (s Service) run(ctx context.Context, binary, dir string, args []string) (CommandResult, error) {
	environment, err := cleanEnvironment()
	if err != nil {
		return CommandResult{}, err
	}
	result, runErr := s.runner()(ctx, binary, dir, args, environment.Variables())
	if cleanupErr := environment.Close(); cleanupErr != nil {
		return result, errors.Join(runErr, fmt.Errorf("remove private local-tool state: %w", cleanupErr))
	}
	return result, runErr
}

func (s Service) runner() Runner {
	if s.Run != nil {
		return s.Run
	}
	return runCommand
}
func (s Service) lookPath() func(string) (string, error) {
	if s.LookPath != nil {
		return s.LookPath
	}
	return exec.LookPath
}
func (s Service) lockPath() func(string) (string, error) {
	if s.LockPath != nil {
		return s.LockPath
	}
	return defaultLockPath
}

func rejectProjectConfig(project Project, allowed bool) error {
	if allowed {
		return nil
	}
	for _, name := range project.ConfigFiles {
		if _, err := os.Lstat(filepath.Join(project.Root, name)); err == nil {
			return fmt.Errorf("local %s package-manager config is present; pass --allow-project-config (or set allow_project_config) only after reviewing registry, proxy, script-shell, and plugin settings", project.Manager)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat local %s package-manager config: %w", project.Manager, err)
		}
	}
	return nil
}

func scanArgs(manager string, minAge int, now time.Time) ([]string, bool) {
	switch manager {
	case "npm":
		args := []string{"outdated", "--json", "--ignore-scripts"}
		if minAge > 0 {
			return append(args, "--before="+now.AddDate(0, 0, -minAge).Format("2006-01-02")), true
		}
		return args, false
	case "pnpm", "bun":
		return []string{"outdated", "--json", "--ignore-scripts"}, false
	case "poetry":
		return []string{"show", "--outdated", "--format", "json", "--no-ansi"}, false
	case "uv":
		return []string{"tree", "--outdated", "--format", "json", "--no-progress"}, false
	case "pip-tools":
		return []string{"list", "--outdated", "--format=json"}, false
	default:
		return nil, false
	}
}

func consistencyArgs(manager string, allowScripts bool) []string {
	ignoreScripts := "--ignore-scripts"
	if allowScripts {
		ignoreScripts = ""
	}
	args := map[string][]string{
		"npm":       compactArgs([]string{"ci", "--dry-run", ignoreScripts}),
		"pnpm":      compactArgs([]string{"install", "--frozen-lockfile", "--lockfile-only", "--dry-run", ignoreScripts}),
		"bun":       compactArgs([]string{"install", "--frozen-lockfile", "--dry-run", ignoreScripts}),
		"poetry":    {"check", "--lock", "--no-ansi"},
		"uv":        {"lock", "--check", "--no-progress"},
		"pip-tools": {"compile", "--dry-run", "--quiet", "requirements.in"},
	}
	return args[manager]
}

func updateArgs(manager string, candidate Candidate, allowScripts bool) []string {
	ignoreScripts := "--ignore-scripts"
	if allowScripts {
		ignoreScripts = ""
	}
	spec := candidate.Name + "@" + candidate.Target
	switch manager {
	case "npm":
		return compactArgs([]string{"install", "--package-lock-only", "--save-exact", ignoreScripts, "--", spec})
	case "pnpm":
		return compactArgs([]string{"update", "--lockfile-only", ignoreScripts, "--", spec})
	case "bun":
		return compactArgs([]string{"update", ignoreScripts, "--", spec})
	case "poetry":
		return []string{"add", "--lock", "--no-interaction", "--no-ansi", "--", spec}
	case "uv":
		return []string{"add", "--no-sync", "--", candidate.Name + "==" + candidate.Target}
	case "pip-tools":
		return []string{"compile", "--only-binary=:all:", "--upgrade-package", candidate.Name + "==" + candidate.Target, "requirements.in"}
	default:
		return nil
	}
}

func compactArgs(args []string) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "" {
			result = append(result, arg)
		}
	}
	return result
}

func validateSelection(policy config.LocalPackagePolicy, available, selected []Candidate) error {
	allowed := make(map[string]bool, len(policy.AllowedPackages))
	for _, name := range policy.AllowedPackages {
		allowed[name] = true
	}
	availableSet := make(map[string]bool, len(available))
	for _, candidate := range available {
		availableSet[candidate.Name+"\x00"+candidate.Target] = true
	}
	seen := make(map[string]bool, len(selected))
	for _, candidate := range selected {
		if !packageNamePattern.MatchString(candidate.Name) || !packageVersionPattern.MatchString(candidate.Target) || strings.HasPrefix(candidate.Name, "-") || strings.HasPrefix(candidate.Target, "-") {
			return fmt.Errorf("invalid package selection %q@%q", candidate.Name, candidate.Target)
		}
		key := candidate.Name + "\x00" + candidate.Target
		if !allowed[candidate.Name] {
			return fmt.Errorf("package %s is not in the local policy allowlist", candidate.Name)
		}
		if seen[key] {
			return fmt.Errorf("duplicate package selection %s@%s", candidate.Name, candidate.Target)
		}
		if !availableSet[key] {
			return fmt.Errorf("selected package %s@%s was not returned by the current local scan", candidate.Name, candidate.Target)
		}
		seen[key] = true
	}
	return nil
}

func parseCandidates(data string) ([]Candidate, error) {
	if strings.TrimSpace(data) == "" {
		return []Candidate{}, nil
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var candidates []Candidate
	collectCandidates(value, &candidates)
	unique := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		candidate.Name, candidate.Current, candidate.Target = safeText(candidate.Name), safeText(candidate.Current), safeText(candidate.Target)
		if packageNamePattern.MatchString(candidate.Name) && packageVersionPattern.MatchString(candidate.Target) && !strings.HasPrefix(candidate.Name, "-") && !strings.HasPrefix(candidate.Target, "-") {
			unique[candidate.Name+"\x00"+candidate.Target] = candidate
		}
	}
	result := make([]Candidate, 0, len(unique))
	for _, candidate := range unique {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func collectCandidates(value any, candidates *[]Candidate) {
	switch record := value.(type) {
	case []any:
		for _, item := range record {
			collectCandidates(item, candidates)
		}
	case map[string]any:
		name, _ := record["name"].(string)
		current := recordString(record, "current", "version", "installed_version")
		target := recordString(record, "latest", "latest_version", "wanted", "target")
		if name != "" && target != "" {
			*candidates = append(*candidates, Candidate{Name: name, Current: current, Target: target})
			return
		}
		for name, item := range record {
			if nested, ok := item.(map[string]any); ok {
				target := recordString(nested, "latest", "latest_version", "wanted", "target")
				if target != "" {
					*candidates = append(*candidates, Candidate{Name: name, Current: recordString(nested, "current", "version"), Target: target})
					continue
				}
			}
			collectCandidates(item, candidates)
		}
	}
}

func recordString(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := record[key].(string); ok {
			return value
		}
	}
	return ""
}

func safeText(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func cleanEnvironment() (*localexec.Environment, error) {
	return localexec.NewEnvironment()
}

// commandOutputTailBytes bounds host memory spent on package-manager output
// (F5-MED-008): only the most recent bytes are retained during the stream and
// a deterministic marker records any drop.
const commandOutputTailBytes = 128 << 10

func runCommand(ctx context.Context, binary, dir string, args, env []string) (CommandResult, error) {
	result, err := localexec.RunTail(ctx, binary, dir, args, env, commandOutputTailBytes)
	return CommandResult{Output: string(result.Output), ExitCode: result.ExitCode}, err
}

func defaultLockPath(root string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve local lock directory: %w", err)
	}
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(cache, "vuelta", "local-locks", fmt.Sprintf("%x.lock", sum[:])), nil
}

type fileState struct {
	mode    fs.FileMode
	size    int64
	modTime time.Time
	digest  string
}

type state map[string]fileState

func projectState(project Project) (state, error) {
	entries, err := os.ReadDir(project.Root)
	if err != nil {
		return nil, err
	}
	result := make(state, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".env") { // never inspect environment files
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		item := fileState{mode: info.Mode(), size: info.Size(), modTime: info.ModTime()}
		if info.Mode().IsRegular() && (name == project.Manifest || name == project.Lock) {
			data, err := os.ReadFile(filepath.Join(project.Root, name))
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(data)
			item.digest = fmt.Sprintf("%x", sum)
		}
		result[name] = item
	}
	return result, nil
}

func (before state) onlyAllowedChanges(after state, project Project) error {
	allowed := map[string]bool{project.Manifest: true, project.Lock: true}
	for name, old := range before {
		current, ok := after[name]
		if !ok {
			if !allowed[name] {
				return fmt.Errorf("local package manager removed unallowlisted path %s", name)
			}
			continue
		}
		if old != current && !allowed[name] {
			return fmt.Errorf("local package manager changed unallowlisted path %s", name)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok && !allowed[name] {
			return fmt.Errorf("local package manager created unallowlisted path %s", name)
		}
	}
	if _, ok := after[project.Manifest]; !ok {
		return fmt.Errorf("local package manager removed manifest %s", project.Manifest)
	}
	if _, ok := after[project.Lock]; !ok {
		return fmt.Errorf("local package manager removed lock file %s", project.Lock)
	}
	return nil
}
