package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

// CandidateScanner discovers available package versions without modifying the
// project. Implementations must return structured candidates, never command
// output that would be persisted in a snapshot.
type CandidateScanner interface {
	Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error)
}

// ResolveCandidateScanner selects the read-only discovery command for a
// workspace. Package manager discovery always uses a read-only container; the
// Docker implementation only reads registry manifests and explicit files.
func ResolveCandidateScanner(ws config.Workspace, cfg config.Config) (CandidateScanner, error) {
	return ResolveCandidateScannerWithOptions(ws, cfg, CandidateScannerOptions{RequireTracked: true})
}

// CandidateScannerOptions binds package discovery to the registered Git
// worktree or to an explicit adhoc input contract.
type CandidateScannerOptions struct {
	AllowProjectConfig bool
	RequireTracked     bool
}

// ResolveCandidateScannerWithOptions selects scanners with exact input
// contracts. Snapshot/update callers require tracked inputs; the read-only
// scan command may defer that integrity check until snapshot creation.
func ResolveCandidateScannerWithOptions(ws config.Workspace, cfg config.Config, options CandidateScannerOptions) (CandidateScanner, error) {
	if err := toolchain.ValidateManagerSupport(ws.Stack, ws.PackageManager); err != nil {
		return nil, err
	}
	var scanners []CandidateScanner
	packageContract, err := scaninput.PackageContract(ws, options.AllowProjectConfig)
	if err != nil {
		return nil, err
	}
	if ws.PackageManager != "" && len(cfg.Update.ToolchainProfiles) > 0 {
		profile, _, _, err := toolchain.Resolve(ws, cfg)
		if err != nil {
			return nil, fmt.Errorf("resolve toolchain profile: %w", err)
		}
		scanner, err := profilePackageScanner(profile, cfg, ws, packageContract, options)
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, scanner)
	} else {
		run := NewReadOnlyDockerRunner(cfg.Update.Egress)
		switch ws.Stack + "/" + ws.PackageManager {
		case "python/poetry":
			image, err := requireImage(cfg, "python-poetry")
			if err != nil {
				return nil, err
			}
			scanners = append(scanners, packageScanner{Kind: "poetry", Image: image, Args: []string{"poetry", "show", "--outdated", "--format", "json"}, Run: run, Contract: packageContract, RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked})
		case "python/uv":
			image, err := requireImage(cfg, "python-uv")
			if err != nil {
				return nil, err
			}
			scanners = append(scanners, packageScanner{Kind: "uv", Image: image, Args: []string{"uv", "tree", "--outdated", "--frozen", "--format", "json"}, Run: run, Contract: packageContract, RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked})
		case "python/pip-tools":
			image, err := requireImage(cfg, "python-pip-tools")
			if err != nil {
				return nil, err
			}
			scanners = append(scanners, packageScanner{Kind: "pip-tools", Image: image, Args: []string{"vuelta-pip-tools-scan"}, Run: run, Contract: packageContract, RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked})
		case "node/npm", "node/bun":
			key := "node"
			launcher := "npx"
			if ws.PackageManager == "bun" {
				key, launcher = "bun", "bunx"
			}
			image, err := requireImage(cfg, key)
			if err != nil {
				return nil, err
			}
			version, err := requireTool(cfg, "npm_check_updates")
			if err != nil {
				return nil, err
			}
			args := []string{launcher, "npm-check-updates@" + version, "--jsonUpgraded", "--removeRange", "--cooldown", strconv.Itoa(cfg.Update.MinReleaseAgeDays * 24)}
			scanners = append(scanners, packageScanner{Kind: ws.PackageManager, Image: image, Args: args, Run: run, Contract: packageContract, RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked})
		case "node/pnpm":
			image, err := requireImage(cfg, "node")
			if err != nil {
				return nil, err
			}
			args := []string{"pnpm", "outdated", "--format", "json", "--config.minimumReleaseAge=" + strconv.Itoa(cfg.Update.MinReleaseAgeDays)}
			scanners = append(scanners, packageScanner{Kind: "pnpm", Image: image, Args: args, Run: run, Contract: packageContract, RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked})
		case "docker/":
		default:
			return nil, fmt.Errorf("no snapshot scanner for stack=%q package_manager=%q", ws.Stack, ws.PackageManager)
		}
	}
	if ws.DockerImages != nil {
		scanners = append(scanners, dockerCandidateScanner{
			Files: ws.DockerImages.Files, Resolve: ResolveDigestViaManifest,
			Contract: scaninput.DockerContract(ws), RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked,
		})
	}
	return combinedScanner(scanners), nil
}

// ResolveToolchainProfile returns the exact profile used by production scan
// and update paths. A nil profile indicates a legacy config without a catalog.
func ResolveToolchainProfile(ws config.Workspace, cfg config.Config) (*config.ToolchainProfile, *toolchain.Identity, error) {
	if ws.PackageManager == "" || len(cfg.Update.ToolchainProfiles) == 0 {
		return nil, nil, nil
	}
	profile, identity, _, err := toolchain.Resolve(ws, cfg)
	if err != nil {
		return nil, nil, err
	}
	return &profile, &identity, nil
}

func profilePackageScanner(profile config.ToolchainProfile, cfg config.Config, ws config.Workspace, contract scaninput.Contract, options CandidateScannerOptions) (packageScanner, error) {
	if expected := map[string]string{"npm": "ncu", "pnpm": "pnpm", "bun": "ncu", "poetry": "poetry", "uv": "uv", "pip-tools": "vuelta-pip-tools-scan"}[ws.PackageManager]; profile.Scanner != expected {
		return packageScanner{}, fmt.Errorf("toolchain profile %q scanner %q is incompatible with %s", profile.ID, profile.Scanner, ws.PackageManager)
	}
	var args []string
	switch ws.PackageManager {
	case "npm", "bun":
		// Snapshot candidates must contain exact versions. By default ncu
		// preserves the manifest range (for example "^4.0.3") in JSON output.
		args = []string{"ncu", "--jsonUpgraded", "--removeRange"}
		if cfg.Update.MinReleaseAgeDays > 0 {
			if !profile.Capabilities.ReleaseAge {
				return packageScanner{}, fmt.Errorf("toolchain profile %q cannot enforce the configured release-age gate", profile.ID)
			}
			args = append(args, "--cooldown", strconv.Itoa(cfg.Update.MinReleaseAgeDays*24))
		}
	case "pnpm":
		args = []string{"pnpm", "outdated", "--format", "json"}
		if cfg.Update.MinReleaseAgeDays > 0 {
			if !profile.Capabilities.ReleaseAge {
				return packageScanner{}, fmt.Errorf("toolchain profile %q cannot enforce the configured release-age gate", profile.ID)
			}
			args = append(args, "--config.minimumReleaseAge="+strconv.Itoa(cfg.Update.MinReleaseAgeDays*24*60))
		}
	case "poetry":
		args = []string{"poetry", "show", "--outdated", "--format", "json"}
	case "uv":
		args = []string{"uv", "tree", "--outdated", "--frozen", "--format", "json"}
	case "pip-tools":
		args = []string{"vuelta-pip-tools-scan"}
	default:
		return packageScanner{}, fmt.Errorf("no profile scanner for package manager %q", ws.PackageManager)
	}
	return packageScanner{
		Kind: ws.PackageManager, Image: profile.Image, Args: args,
		Run: NewReadOnlyDockerRunnerForProfile(cfg.Update.Egress, profile.User, profile.Platform), Contract: contract,
		RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked,
	}, nil
}

type combinedScanner []CandidateScanner

func (s combinedScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	var candidates []updatesnapshot.Candidate
	for _, scanner := range s {
		found, err := scanner.Scan(ctx, projectPath)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, found...)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Kind+"/"+candidates[i].Name < candidates[j].Kind+"/"+candidates[j].Name
	})
	return candidates, nil
}

type packageScanner struct {
	Kind, Image    string
	Args           []string
	Run            ReadOnlyDockerRunner
	Contract       scaninput.Contract
	RepositoryRoot string
	RequireTracked bool
}

func (s packageScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	bundle, err := scaninput.Build(ctx, projectPath, s.RepositoryRoot, scaninput.Options{RequireTracked: s.RequireTracked}, s.Contract)
	if err != nil {
		return nil, err
	}
	defer bundle.Destroy()
	out, err := s.Run(ctx, s.Image, s.Args, bundle)
	if err != nil && !acceptedDiscoveryExit(s.Kind, err) {
		return nil, err
	}
	candidates, err := parsePackageCandidates(s.Kind, []byte(out))
	if err != nil {
		return nil, fmt.Errorf("parse %s update candidates: %w", s.Kind, err)
	}
	return candidates, nil
}

type exitCoder interface {
	ExitCode() int
}

// pnpm outdated deliberately exits 1 when it successfully finds outdated
// dependencies. The output is still treated as untrusted and must pass the
// same strict JSON/candidate validation before it can become a plan.
func acceptedDiscoveryExit(kind string, err error) bool {
	if kind != "pnpm" {
		return false
	}
	var exit exitCoder
	return errors.As(err, &exit) && exit.ExitCode() == 1
}

// parsePackageCandidates accepts the JSON shapes emitted by Poetry, the
// pip-tools metadata scanner, pnpm, uv, and npm-check-updates. Unknown or
// malformed records are rejected so
// untrusted registry metadata can never become an executable update plan.
func parsePackageCandidates(kind string, data []byte) ([]updatesnapshot.Candidate, error) {
	// Some scanner tools write an informational notice (venv creation, a
	// version-check nag) on the same stream as their JSON output despite a
	// machine-readable flag being requested. Tolerate surrounding text but
	// still require one well-formed JSON value, not an arbitrary blob.
	start := bytes.IndexAny(data, "{[")
	if start < 0 {
		return nil, errors.New("scanner output contains no JSON value")
	}
	var value any
	if err := json.NewDecoder(bytes.NewReader(data[start:])).Decode(&value); err != nil {
		return nil, err
	}
	var candidates []updatesnapshot.Candidate
	collectCandidates(kind, value, &candidates)
	if candidates == nil {
		return []updatesnapshot.Candidate{}, nil
	}
	for _, candidate := range candidates {
		if !validCandidate(candidate) {
			return nil, fmt.Errorf("invalid candidate %q", candidate.Name)
		}
	}
	return candidates, nil
}

func collectCandidates(kind string, value any, candidates *[]updatesnapshot.Candidate) {
	// uv tree --format json returns a dependency graph keyed by opaque
	// "name==version@source" identifiers, not a flat name->record map, so it
	// needs its own extraction instead of the generic heuristic below.
	if kind == "uv" {
		collectUVCandidates(value, candidates)
		return
	}
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			collectCandidates(kind, item, candidates)
		}
	case map[string]any:
		name, _ := v["name"].(string)
		current, _ := firstString(v, "version", "current", "installed_version")
		target, _ := firstString(v, "latest", "latest_version", "wanted", "target")
		if name != "" && target != "" {
			*candidates = append(*candidates, updatesnapshot.Candidate{Kind: kind, Name: name, Current: current, Target: target})
			return
		}
		for key, item := range v {
			if target, ok := item.(string); ok {
				*candidates = append(*candidates, updatesnapshot.Candidate{Kind: kind, Name: key, Target: target})
				continue
			}
			if record, ok := item.(map[string]any); ok {
				if latest, ok := firstString(record, "latest", "latest_version", "wanted"); ok {
					current, _ := firstString(record, "current", "version")
					*candidates = append(*candidates, updatesnapshot.Candidate{Kind: kind, Name: key, Current: current, Target: latest})
				}
			}
		}
	}
}

func collectUVCandidates(value any, candidates *[]updatesnapshot.Candidate) {
	root, ok := value.(map[string]any)
	if !ok {
		return
	}
	resolution, ok := root["resolution"].(map[string]any)
	if !ok {
		return
	}
	for _, item := range resolution {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := record["name"].(string)
		latest, hasLatest := firstString(record, "latest_version")
		if name == "" || !hasLatest {
			continue
		}
		current, _ := firstString(record, "version")
		*candidates = append(*candidates, updatesnapshot.Candidate{Kind: "uv", Name: name, Current: current, Target: latest})
	}
}

func firstString(record map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := record[key].(string); ok {
			return value, true
		}
	}
	return "", false
}

var candidatePartPattern = regexp.MustCompile(`^[A-Za-z0-9@._+!/-]+$`)

func validCandidate(candidate updatesnapshot.Candidate) bool {
	return candidatePartPattern.MatchString(candidate.Name) && candidatePartPattern.MatchString(candidate.Target) && (candidate.Current == "" || candidatePartPattern.MatchString(candidate.Current))
}

type dockerCandidateScanner struct {
	Files          []string
	Resolve        DigestResolver
	Contract       scaninput.Contract
	RepositoryRoot string
	RequireTracked bool
}

func (s dockerCandidateScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	bundle, err := scaninput.Build(ctx, projectPath, s.RepositoryRoot, scaninput.Options{RequireTracked: s.RequireTracked}, s.Contract)
	if err != nil {
		return nil, err
	}
	defer bundle.Destroy()
	var candidates []updatesnapshot.Candidate
	for _, rel := range s.Files {
		data, ok := bundle.Content(rel)
		if !ok {
			return nil, fmt.Errorf("validated Docker scan input %s is unavailable", rel)
		}
		for _, match := range imageReferences(string(data)) {
			digest, err := s.Resolve(ctx, match.ref)
			if err != nil {
				return nil, fmt.Errorf("resolve digest for %s: %w", match.ref, err)
			}
			if digest != match.digest {
				candidates = append(candidates, updatesnapshot.Candidate{Kind: "docker", Name: match.ref, Current: match.digest, Target: digest, File: rel})
			}
		}
	}
	return candidates, nil
}

type imageReference struct{ ref, digest string }

func imageReferences(content string) []imageReference {
	var refs []imageReference
	for _, line := range strings.Split(content, "\n") {
		match := fromLinePattern.FindStringSubmatch(line)
		if match == nil {
			match = imageLinePattern.FindStringSubmatch(line)
		}
		if match != nil && match[3] != "" {
			refs = append(refs, imageReference{ref: match[2], digest: strings.TrimPrefix(match[3], "@")})
		}
	}
	return refs
}

// PlannedUpdater executes only the candidate names and target versions stored
// in a validated snapshot. Validate and Recheck are run before the first
// mutable command; a failed check therefore leaves the sandbox untouched.
type PlannedUpdater struct {
	Candidates   []updatesnapshot.Candidate
	Workspace    config.Workspace
	Config       config.Config
	AllowScripts bool
	Validate     func(context.Context) error
	Recheck      CandidateScanner
	Run          DockerRunner
}

func (u PlannedUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	if u.Validate == nil || u.Recheck == nil {
		return false, errors.New("snapshot updater is missing validation")
	}
	if err := u.Validate(ctx); err != nil {
		return false, err
	}
	current, err := u.Recheck.Scan(ctx, u.Workspace.Path)
	if err != nil {
		return false, fmt.Errorf("recheck snapshot candidates: %w", err)
	}
	if !containsAll(current, u.Candidates) {
		return false, fmt.Errorf("snapshot candidate no longer exists")
	}
	return u.apply(ctx, projectPath)
}

func containsAll(current, planned []updatesnapshot.Candidate) bool {
	seen := make(map[string]bool, len(current))
	for _, candidate := range current {
		seen[candidate.Kind+"\x00"+candidate.Name+"\x00"+candidate.Target+"\x00"+candidate.File] = true
	}
	for _, candidate := range planned {
		if !seen[candidate.Kind+"\x00"+candidate.Name+"\x00"+candidate.Target+"\x00"+candidate.File] {
			return false
		}
	}
	return true
}

func (u PlannedUpdater) apply(ctx context.Context, projectPath string) (bool, error) {
	if len(u.Candidates) == 0 {
		return false, nil
	}
	changed := false
	if hasDockerCandidates(u.Candidates) {
		dockerChanged, err := plannedDockerUpdater{Candidates: u.Candidates}.Update(ctx, projectPath)
		if err != nil || onlyDocker(u.Candidates) {
			return dockerChanged, err
		}
		changed = dockerChanged
	}
	profile, _, err := ResolveToolchainProfile(u.Workspace, u.Config)
	if err != nil {
		return false, fmt.Errorf("resolve toolchain profile: %w", err)
	}
	user := ""
	platform := ""
	if profile != nil {
		user = profile.User
		platform = profile.Platform
	}
	runner := u.Run
	if runner == nil {
		runner = NewDockerRunnerForProfile(u.Config.Update.Egress, user, platform)
	}
	image, err := plannedImage(u.Workspace, u.Config, profile)
	if err != nil {
		return false, err
	}
	before, err := plannedLockDigest(u.Workspace, projectPath)
	if err != nil {
		return false, err
	}
	packageCandidates := nonDockerCandidates(u.Candidates)
	if u.Workspace.PackageManager == "pip-tools" && len(packageCandidates) > 0 {
		for _, candidate := range packageCandidates {
			if err := rewritePipToolsPin(projectPath, candidate); err != nil {
				return false, err
			}
		}
		if _, err := runner(ctx, image, []string{"pip-compile", "requirements.in"}, projectPath); err != nil {
			return false, err
		}
	} else {
		for _, candidate := range packageCandidates {
			args, err := plannedArgs(u.Workspace.PackageManager, candidate, u.Config, profile, u.AllowScripts)
			if err != nil {
				return false, err
			}
			if _, err := runner(ctx, image, args, projectPath); err != nil {
				return false, err
			}
		}
	}
	if u.Workspace.PackageManager == "npm" {
		args := []string{"npm", "install", "--no-audit", "--no-fund"}
		if !u.AllowScripts {
			args = append(args, "--ignore-scripts")
		}
		_, err = runner(ctx, image, args, projectPath)
		if err == nil {
			err = validateNPMCandidateTargets(projectPath, packageCandidates)
		}
	}
	if u.Workspace.PackageManager == "bun" {
		args := []string{"bun", "install", "--lockfile-only"}
		if !u.AllowScripts {
			args = append(args, "--ignore-scripts")
		}
		_, err = runner(ctx, image, args, projectPath)
	}
	if err != nil {
		return false, err
	}
	after, err := plannedLockDigest(u.Workspace, projectPath)
	if err != nil {
		return false, err
	}
	return changed || before != after, nil
}

func plannedArgs(manager string, candidate updatesnapshot.Candidate, cfg config.Config, profile *config.ToolchainProfile, allowScripts bool) ([]string, error) {
	if !validCandidate(candidate) {
		return nil, errors.New("invalid snapshot candidate")
	}
	switch manager {
	case "poetry":
		// poetry update respects an existing exact pin in pyproject.toml and
		// silently no-ops instead of moving past it; poetry add rewrites the
		// pin itself, matching how the other managers' updaters behave.
		return []string{"poetry", "add", candidate.Name + "==" + candidate.Target}, nil
	case "uv":
		// uv lock --upgrade-package only nudges resolution and fails closed
		// ("unsatisfiable") against an existing exact pin; uv add rewrites the
		// pin itself. --no-sync keeps this to a manifest/lock change instead
		// of installing into a project-local .venv inside the sandbox.
		return []string{"uv", "add", candidate.Name + "==" + candidate.Target, "--no-sync"}, nil
	case "pip-tools":
		return nil, errors.New("pip-tools updates require manifest pin rewriting before pip-compile")
	case "npm":
		if profile != nil {
			return plannedNCUArgs("ncu", candidate.Name, cfg.Update.MinReleaseAgeDays), nil
		}
		version, err := requireTool(cfg, "npm_check_updates")
		if err != nil {
			return nil, err
		}
		return plannedNCUArgs("npx", candidate.Name, cfg.Update.MinReleaseAgeDays, "npm-check-updates@"+version), nil
	case "pnpm":
		args := []string{"pnpm", "update", "--lockfile-only"}
		if !allowScripts {
			args = append(args, "--ignore-scripts")
		}
		return append(args, candidate.Name+"@"+candidate.Target), nil
	case "bun":
		if profile != nil {
			return []string{"ncu", "--filter", candidate.Name + "@" + candidate.Target, "-u"}, nil
		}
		version, err := requireTool(cfg, "npm_check_updates")
		if err != nil {
			return nil, err
		}
		return []string{"bunx", "npm-check-updates@" + version, "--filter", candidate.Name + "@" + candidate.Target, "-u"}, nil
	default:
		return nil, fmt.Errorf("no planned update command for %q", manager)
	}
}

func plannedNCUArgs(launcher, name string, minReleaseAgeDays int, prefix ...string) []string {
	args := []string{launcher}
	args = append(args, prefix...)
	args = append(args, "--filter", name)
	if minReleaseAgeDays > 0 {
		args = append(args, "--cooldown", strconv.Itoa(minReleaseAgeDays*24))
	}
	return append(args, "-u")
}

func validateNPMCandidateTargets(root string, candidates []updatesnapshot.Candidate) error {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return fmt.Errorf("read updated package.json: %w", err)
	}
	var manifest struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse updated package.json: %w", err)
	}
	sections := []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies}
	for _, candidate := range candidates {
		if candidate.Kind != "npm" {
			continue
		}
		matches := 0
		spec := ""
		for _, section := range sections {
			if value, ok := section[candidate.Name]; ok {
				matches++
				spec = value
			}
		}
		if matches != 1 || !npmSpecTargets(spec, candidate.Target) {
			return fmt.Errorf("npm candidate %q was not pinned to reviewed target %q", candidate.Name, candidate.Target)
		}
	}
	return nil
}

func npmSpecTargets(spec, target string) bool {
	value := strings.TrimSpace(spec)
	for _, prefix := range []string{">=", "<=", "^", "~", ">", "<", "="} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimSpace(strings.TrimPrefix(value, prefix))
			break
		}
	}
	value = strings.TrimPrefix(value, "v")
	return value == target
}

func plannedImage(ws config.Workspace, cfg config.Config, profile *config.ToolchainProfile) (string, error) {
	if profile != nil {
		return profile.Image, nil
	}
	switch ws.PackageManager {
	case "poetry":
		return requireImage(cfg, "python-poetry")
	case "uv":
		return requireImage(cfg, "python-uv")
	case "pip-tools":
		return requireImage(cfg, "python-pip-tools")
	case "npm", "pnpm":
		return requireImage(cfg, "node")
	case "bun":
		return requireImage(cfg, "bun")
	}
	return "", fmt.Errorf("no image for package manager %q", ws.PackageManager)
}

func plannedLockDigest(ws config.Workspace, projectPath string) (string, error) {
	file := map[string]string{"poetry": "poetry.lock", "uv": "uv.lock", "pip-tools": "requirements.txt", "npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "bun": "bun.lock"}[ws.PackageManager]
	return lockDigest(projectPath, file)
}

func nonDockerCandidates(candidates []updatesnapshot.Candidate) []updatesnapshot.Candidate {
	result := make([]updatesnapshot.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Kind != "docker" {
			result = append(result, candidate)
		}
	}
	return result
}

var pipToolsPinPattern = regexp.MustCompile(`^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^]\r\n]+\])?(\s*==\s*)([A-Za-z0-9][A-Za-z0-9.!+_-]*)(\s*(?:#.*)?)$`)
var pythonNameSeparatorPattern = regexp.MustCompile(`[-_.]+`)

func rewritePipToolsPin(projectPath string, candidate updatesnapshot.Candidate) error {
	if candidate.Current == "" {
		return fmt.Errorf("pip-tools candidate %q has no current exact pin", candidate.Name)
	}
	path := filepath.Join(projectPath, "requirements.in")
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect requirements.in: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("requirements.in must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read requirements.in: %w", err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	wanted := normalizePythonPackage(candidate.Name)
	matches := 0
	for index, lineWithEnding := range lines {
		line := strings.TrimSuffix(lineWithEnding, "\n")
		ending := strings.TrimPrefix(lineWithEnding, line)
		parts := pipToolsPinPattern.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if parts == nil || normalizePythonPackage(parts[2]) != wanted {
			continue
		}
		matches++
		if parts[5] != candidate.Current {
			return fmt.Errorf("pip-tools pin for %q changed from snapshot version %q", candidate.Name, candidate.Current)
		}
		carriageReturn := ""
		if strings.HasSuffix(line, "\r") {
			carriageReturn = "\r"
		}
		lines[index] = parts[1] + parts[2] + parts[3] + parts[4] + candidate.Target + parts[6] + carriageReturn + ending
	}
	if matches != 1 {
		return fmt.Errorf("requirements.in must contain exactly one direct exact pin for %q", candidate.Name)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), info.Mode().Perm()); err != nil {
		return fmt.Errorf("write requirements.in: %w", err)
	}
	return nil
}

func normalizePythonPackage(name string) string {
	return strings.ToLower(pythonNameSeparatorPattern.ReplaceAllString(name, "-"))
}

func hasDockerCandidates(candidates []updatesnapshot.Candidate) bool {
	for _, candidate := range candidates {
		if candidate.Kind == "docker" {
			return true
		}
	}
	return false
}
func onlyDocker(candidates []updatesnapshot.Candidate) bool {
	for _, candidate := range candidates {
		if candidate.Kind != "docker" {
			return false
		}
	}
	return true
}

type plannedDockerUpdater struct{ Candidates []updatesnapshot.Candidate }

func (u plannedDockerUpdater) Update(_ context.Context, projectPath string) (bool, error) {
	changed := false
	for _, candidate := range u.Candidates {
		if candidate.Kind != "docker" {
			continue
		}
		if filepath.IsAbs(candidate.File) || candidate.File == "" || candidate.File == ".." || strings.HasPrefix(filepath.Clean(candidate.File), ".."+string(filepath.Separator)) {
			return changed, errors.New("invalid docker snapshot file")
		}
		path := filepath.Join(projectPath, candidate.File)
		data, err := os.ReadFile(path)
		if err != nil {
			return changed, err
		}
		old := candidate.Name + "@" + candidate.Current
		newRef := candidate.Name + "@" + candidate.Target
		if !strings.Contains(string(data), old) {
			return changed, fmt.Errorf("docker candidate %s is no longer present", candidate.Name)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), old, newRef)), 0o644); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}
