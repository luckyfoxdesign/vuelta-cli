package updater

import (
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
	var scanners []CandidateScanner
	run := NewReadOnlyDockerRunner(cfg.Update.Egress)
	switch ws.Stack + "/" + ws.PackageManager {
	case "python/poetry":
		image, err := requireImage(cfg, "python-poetry")
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, packageScanner{Kind: "poetry", Image: image, Args: []string{"poetry", "show", "--outdated", "--format", "json"}, Run: run})
	case "python/uv":
		image, err := requireImage(cfg, "python-uv")
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, packageScanner{Kind: "uv", Image: image, Args: []string{"uv", "tree", "--outdated", "--format", "json"}, Run: run})
	case "python/pip-tools":
		image, err := requireImage(cfg, "python-pip-tools")
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, packageScanner{Kind: "pip-tools", Image: image, Args: []string{"pip", "list", "--outdated", "--format=json"}, Run: run})
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
		args := []string{launcher, "npm-check-updates@" + version, "--jsonUpgraded", "--cooldown", strconv.Itoa(cfg.Update.MinReleaseAgeDays * 24)}
		scanners = append(scanners, packageScanner{Kind: ws.PackageManager, Image: image, Args: args, Run: run})
	case "node/pnpm":
		image, err := requireImage(cfg, "node")
		if err != nil {
			return nil, err
		}
		args := []string{"pnpm", "outdated", "--format", "json", "--config.minimumReleaseAge=" + strconv.Itoa(cfg.Update.MinReleaseAgeDays)}
		scanners = append(scanners, packageScanner{Kind: "pnpm", Image: image, Args: args, Run: run})
	case "docker/":
	default:
		return nil, fmt.Errorf("no snapshot scanner for stack=%q package_manager=%q", ws.Stack, ws.PackageManager)
	}
	if ws.DockerImages != nil {
		scanners = append(scanners, dockerCandidateScanner{Files: ws.DockerImages.Files, Resolve: ResolveDigestViaManifest})
	}
	return combinedScanner(scanners), nil
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
	Kind, Image string
	Args        []string
	Run         DockerRunner
}

func (s packageScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	out, err := s.Run(ctx, s.Image, s.Args, projectPath)
	if err != nil {
		return nil, err
	}
	candidates, err := parsePackageCandidates(s.Kind, []byte(out))
	if err != nil {
		return nil, fmt.Errorf("parse %s update candidates: %w", s.Kind, err)
	}
	return candidates, nil
}

// parsePackageCandidates accepts the JSON shapes emitted by Poetry, pip,
// pnpm, uv, and npm-check-updates. Unknown/malformed records are rejected so
// untrusted registry metadata can never become an executable update plan.
func parsePackageCandidates(kind string, data []byte) ([]updatesnapshot.Candidate, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
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

func firstString(record map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := record[key].(string); ok {
			return value, true
		}
	}
	return "", false
}

var candidatePartPattern = regexp.MustCompile(`^[A-Za-z0-9@._+/-]+$`)

func validCandidate(candidate updatesnapshot.Candidate) bool {
	return candidatePartPattern.MatchString(candidate.Name) && candidatePartPattern.MatchString(candidate.Target) && (candidate.Current == "" || candidatePartPattern.MatchString(candidate.Current))
}

type dockerCandidateScanner struct {
	Files   []string
	Resolve DigestResolver
}

func (s dockerCandidateScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	var candidates []updatesnapshot.Candidate
	for _, rel := range s.Files {
		data, err := os.ReadFile(filepath.Join(projectPath, rel))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
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
	runner := NewDockerRunner(u.Config.Update.Egress)
	image, err := plannedImage(u.Workspace, u.Config)
	if err != nil {
		return false, err
	}
	before, err := plannedLockDigest(u.Workspace, projectPath)
	if err != nil {
		return false, err
	}
	for _, candidate := range u.Candidates {
		if candidate.Kind == "docker" {
			continue
		}
		args, err := plannedArgs(u.Workspace.PackageManager, candidate, u.Config, u.AllowScripts)
		if err != nil {
			return false, err
		}
		if _, err := runner(ctx, image, args, projectPath); err != nil {
			return false, err
		}
	}
	if u.Workspace.PackageManager == "npm" {
		args := []string{"npm", "install", "--package-lock-only"}
		if !u.AllowScripts {
			args = append(args, "--ignore-scripts")
		}
		_, err = runner(ctx, image, args, projectPath)
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

func plannedArgs(manager string, candidate updatesnapshot.Candidate, cfg config.Config, allowScripts bool) ([]string, error) {
	if !validCandidate(candidate) {
		return nil, errors.New("invalid snapshot candidate")
	}
	switch manager {
	case "poetry":
		return []string{"poetry", "update", candidate.Name}, nil
	case "uv":
		return []string{"uv", "lock", "--upgrade-package", candidate.Name + "==" + candidate.Target}, nil
	case "pip-tools":
		return []string{"pip-compile", "--upgrade-package", candidate.Name + "==" + candidate.Target, "requirements.in"}, nil
	case "npm":
		version, err := requireTool(cfg, "npm_check_updates")
		if err != nil {
			return nil, err
		}
		return []string{"npx", "npm-check-updates@" + version, "--filter", candidate.Name + "@" + candidate.Target, "-u"}, nil
	case "pnpm":
		args := []string{"pnpm", "update", "--lockfile-only"}
		if !allowScripts {
			args = append(args, "--ignore-scripts")
		}
		return append(args, candidate.Name+"@"+candidate.Target), nil
	case "bun":
		version, err := requireTool(cfg, "npm_check_updates")
		if err != nil {
			return nil, err
		}
		return []string{"bunx", "npm-check-updates@" + version, "--filter", candidate.Name + "@" + candidate.Target, "-u"}, nil
	default:
		return nil, fmt.Errorf("no planned update command for %q", manager)
	}
}

func plannedImage(ws config.Workspace, cfg config.Config) (string, error) {
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
