package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/localexec"
	"github.com/luckyfoxdesign/vuelta/internal/localupdate"
	"github.com/luckyfoxdesign/vuelta/internal/pipeline"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const (
	exitEnv                        = 4
	exitFindings                   = 5
	localScannerStdoutMaxBytes     = 64 << 20
	localScannerStderrTailMaxBytes = 64 << 10
)

type scanTarget struct {
	workspace *config.Workspace
	name      string
	path      string
	origin    string
}

type scanToolResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type scanResult struct {
	Project         string                     `json:"project,omitempty"`
	Directory       string                     `json:"directory"`
	Origin          string                     `json:"origin"`
	Execution       string                     `json:"execution"`
	Status          string                     `json:"status"`
	SnapshotID      string                     `json:"snapshot_id,omitempty"`
	Candidates      []updatesnapshot.Candidate `json:"candidates"`
	Vulnerabilities []string                   `json:"vulnerabilities"`
	Tools           []scanToolResult           `json:"tools"`
	Warnings        []string                   `json:"warnings"`
	Error           *jsonCommandError          `json:"error,omitempty"`
}

type scanSummary struct {
	Succeeded       int `json:"succeeded"`
	Failed          int `json:"failed"`
	Ready           int `json:"ready"`
	Clean           int `json:"clean"`
	Candidates      int `json:"candidates"`
	Vulnerabilities int `json:"vulnerabilities"`
}

type scanOptions struct {
	project            string
	directory          string
	all                bool
	only               string
	policyPath         string
	minReleaseAge      string
	allowProjectConfig bool
	execution          string
	failOn             string
	jsonOutput         bool
}

func executeScan(args []string) error {
	options, configFile, err := parseScanOptions(args)
	if err != nil {
		return scanTopLevelFailure(options.jsonOutput || scanJSONRequested(args), "invalid_invocation", err, "Run vuelta help scan for usage")
	}
	cfg, loadErr := config.Load(configFile)
	if loadErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "config_unreadable", fail(exitConfig, "%v", loadErr), "Create or select a valid config with --config")
	}
	warnings := configWarnings(cfg)
	if validateErr := cfg.Validate(); validateErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "config_invalid", fail(exitConfig, "%v", validateErr), "Run vuelta config validate for details")
	}
	targets, targetErr := resolveScanTargets(*cfg, options, currentDirectory)
	if targetErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "target_invalid", fail(exitConfig, "%v", targetErr), "Choose one of --project, --directory, or --all")
	}
	if executionErr := validateScanExecution(targets, options); executionErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "invalid_execution", fail(exitConfig, "%v", executionErr), "Use --execution container or select an unregistered --directory")
	}
	policy, policyIdentity, policyErr := loadScanPolicy(options.policyPath)
	if policyErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "policy_invalid", fail(exitConfig, "%v", policyErr), "Review --policy and run scan again")
	}
	minAge, minAgeErr := effectiveMinReleaseAge(options.minReleaseAge, cfg.Update.MinReleaseAgeDays, policy.MinReleaseAgeDays)
	if minAgeErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "invalid_invocation", fail(exitConfig, "%v", minAgeErr), "Use 0, a Go duration such as 168h, or a day duration such as 7d")
	}
	if err := preflightScanEnvironment(*cfg, targets, options); err != nil {
		return scanTopLevelFailure(options.jsonOutput, "environment_unavailable", fail(exitEnv, "%v", err), "Install the required tool or choose an allowed execution mode")
	}

	results := make([]scanResult, 0, len(targets))
	for _, target := range targets {
		results = append(results, scanOneTarget(context.Background(), *cfg, target, options, policy, policyIdentity, minAge))
	}
	summary := summarizeScan(results)
	if options.jsonOutput {
		if err := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "scan", Results: results, Summary: summary,
			Warnings: warnings, Errors: []jsonCommandError{},
		}); err != nil {
			return err
		}
	} else {
		for _, warning := range warnings {
			fmt.Fprintln(os.Stderr, "warning:", warning)
		}
		writeHumanScanResults(results, configFile)
	}
	return scanResultError(summary, options.failOn)
}

func validateScanExecution(targets []scanTarget, options scanOptions) error {
	for _, target := range targets {
		if target.origin == updatesnapshot.OriginWorkspace && options.execution == "local" {
			return fmt.Errorf("registered project %q is container-only; --execution local is allowed only with an unregistered --directory", target.name)
		}
	}
	return nil
}

func scanResultError(summary scanSummary, failOn string) error {
	if summary.Failed > 0 {
		return fail(exitFailure, "%d scan target(s) failed", summary.Failed)
	}
	if failOn == "vulnerabilities" && summary.Vulnerabilities > 0 {
		return fail(exitFindings, "%d vulnerability finding(s)", summary.Vulnerabilities)
	}
	return nil
}

func parseScanOptions(args []string) (scanOptions, string, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var options scanOptions
	fs.StringVar(&options.project, "project", "", "scan one configured project")
	fs.StringVar(&options.project, "p", "", "scan one configured project")
	fs.StringVar(&options.directory, "directory", "", "scan an explicit directory")
	fs.StringVar(&options.directory, "d", "", "scan an explicit directory")
	fs.BoolVar(&options.all, "all", false, "scan every configured project")
	fs.StringVar(&options.only, "only", "", "scan only vulnerabilities or packages")
	fs.StringVar(&options.policyPath, "policy", "", "standalone package policy")
	fs.StringVar(&options.minReleaseAge, "min-release-age", "", "minimum release age")
	fs.BoolVar(&options.allowProjectConfig, "allow-project-config", false, "honor reviewed package-manager config")
	fs.StringVar(&options.execution, "execution", "container", "container or local")
	fs.StringVar(&options.failOn, "fail-on", "", "return 5 for vulnerability findings")
	fs.BoolVar(&options.jsonOutput, "json", false, "write the versioned JSON envelope")
	if err := fs.Parse(args); err != nil {
		return options, "", fail(exitConfig, "%v", err)
	}
	if optionOccurrences(args, "-p", "--project") > 1 {
		return options, "", fail(exitConfig, "--project may be specified only once")
	}
	if optionOccurrences(args, "-d", "--directory") > 1 {
		return options, "", fail(exitConfig, "--directory may be specified only once")
	}
	if options.only != "" && options.only != "vulnerabilities" && options.only != "packages" {
		return options, "", fail(exitConfig, "--only must be vulnerabilities or packages")
	}
	if options.execution != "container" && options.execution != "local" {
		return options, "", fail(exitConfig, "--execution must be container or local")
	}
	if options.failOn != "" && options.failOn != "vulnerabilities" {
		return options, "", fail(exitConfig, "--fail-on must be vulnerabilities")
	}
	if options.only == "packages" && options.failOn != "" {
		return options, "", fail(exitConfig, "--fail-on vulnerabilities requires a vulnerability scan")
	}
	selectors := 0
	for _, selected := range []bool{options.project != "", options.directory != "", options.all} {
		if selected {
			selectors++
		}
	}
	if selectors > 1 {
		return options, "", fail(exitConfig, "--project, --directory, and --all are mutually exclusive")
	}
	configFile, err := configPath(fs.Args())
	return options, configFile, err
}

func optionOccurrences(args []string, names ...string) int {
	count := 0
	for _, argument := range args {
		if argument == "--" {
			break
		}
		name, _, _ := strings.Cut(argument, "=")
		for _, candidate := range names {
			if name == candidate {
				count++
				break
			}
		}
	}
	return count
}

func scanJSONRequested(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || strings.HasPrefix(argument, "--json=") {
			return true
		}
	}
	return false
}

var currentDirectory = os.Getwd

func resolveScanTargets(cfg config.Config, options scanOptions, getwd func() (string, error)) ([]scanTarget, error) {
	registered := make([]scanTarget, 0, len(cfg.Workspaces))
	for index := range cfg.Workspaces {
		canonical, err := canonicalDirectory(cfg.Workspaces[index].Path)
		if err != nil {
			return nil, fmt.Errorf("canonicalize project %q: %w", config.WorkspaceName(cfg.Workspaces[index]), err)
		}
		registered = append(registered, scanTarget{workspace: &cfg.Workspaces[index], name: config.WorkspaceName(cfg.Workspaces[index]), path: canonical, origin: updatesnapshot.OriginWorkspace})
	}
	if options.all {
		if len(registered) == 0 {
			return nil, errors.New("--all requires at least one configured project")
		}
		return registered, nil
	}
	if options.project != "" {
		for _, target := range registered {
			if target.name == options.project {
				return []scanTarget{target}, nil
			}
		}
		return nil, fmt.Errorf("project %q is not configured", options.project)
	}
	selectedPath := options.directory
	if selectedPath == "" {
		cwd, err := getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve current directory: %w", err)
		}
		selectedPath = cwd
	}
	canonical, err := canonicalDirectory(selectedPath)
	if err != nil {
		return nil, err
	}
	matched, err := containingRegisteredTarget(registered, canonical)
	if err != nil {
		return nil, err
	}
	if matched != nil {
		return []scanTarget{*matched}, nil
	}
	if options.directory == "" {
		return nil, errors.New("current directory is not inside a registered project\nTry: vuelta scan --directory .\n     vuelta project add .\n     vuelta scan --all")
	}
	return []scanTarget{{path: canonical, origin: updatesnapshot.OriginAdhoc}}, nil
}

func containingRegisteredTarget(targets []scanTarget, path string) (*scanTarget, error) {
	var matches []scanTarget
	longest := -1
	for _, target := range targets {
		if !pathContains(target.path, path) {
			continue
		}
		length := len(target.path)
		if length > longest {
			matches = []scanTarget{target}
			longest = length
		} else if length == longest {
			matches = append(matches, target)
		}
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("configured projects %q and %q ambiguously contain %s", matches[0].name, matches[1].name, path)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return &matches[0], nil
}

func pathContains(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func canonicalDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("make path absolute: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve directory %s: %w", path, err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", path)
	}
	return canonical, nil
}

func loadScanPolicy(path string) (config.LocalPackagePolicy, updatesnapshot.PolicyIdentity, error) {
	if path == "" {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{Path: updatesnapshot.PolicyNone, Hash: updatesnapshot.PolicyNone}, nil
	}
	canonical, err := filepath.Abs(path)
	if err != nil {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, fmt.Errorf("canonicalize policy: %w", err)
	}
	canonical, err = filepath.EvalSymlinks(canonical)
	if err != nil {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, fmt.Errorf("canonicalize policy: %w", err)
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, fmt.Errorf("policy must be a regular file: %s", canonical)
	}
	policy, err := config.LoadLocalPackagePolicy(canonical)
	if err != nil {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, err
	}
	if policy.AllowProjectConfig {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, errors.New("scan policy cannot authorize project package-manager configuration; pass --allow-project-config explicitly")
	}
	data, err := os.ReadFile(canonical)
	if err != nil {
		return config.LocalPackagePolicy{}, updatesnapshot.PolicyIdentity{}, fmt.Errorf("read policy: %w", err)
	}
	sum := sha256.Sum256(data)
	return policy, updatesnapshot.PolicyIdentity{Path: canonical, Hash: fmt.Sprintf("%x", sum)}, nil
}

func effectiveMinReleaseAge(value string, configuredDays, policyDays int) (time.Duration, error) {
	if value == "" {
		days := configuredDays
		if policyDays > days {
			days = policyDays
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if value == "0" {
		return 0, nil
	}
	if strings.HasSuffix(value, "d") {
		var days int
		if _, err := fmt.Sscanf(value, "%dd", &days); err != nil || days < 0 || fmt.Sprintf("%dd", days) != value {
			return 0, fmt.Errorf("invalid --min-release-age %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("invalid --min-release-age %q", value)
	}
	return duration, nil
}

func preflightScanEnvironment(cfg config.Config, targets []scanTarget, options scanOptions) error {
	return preflightScanEnvironmentWith(cfg, targets, options, nil)
}

func preflightScanEnvironmentWith(cfg config.Config, targets []scanTarget, options scanOptions, resolve localexec.Resolver) error {
	if options.execution == "container" {
		if _, err := dockerexec.Default().Path(); err != nil {
			return errors.New("docker is required for container execution; for an adhoc directory, explicitly choose --execution local")
		}
	}
	if options.only != "vulnerabilities" {
		for _, target := range targets {
			if target.workspace != nil {
				if _, err := gitexec.Default().Path(); err != nil {
					return errors.New("git is required to bind registered project snapshots to their current revision")
				}
				break
			}
		}
	}
	if options.execution == "local" && options.only != "packages" {
		if cfg.VulnScan.DependencySource != "trivy" && cfg.VulnScan.DependencySource != "osv-scanner" {
			return fmt.Errorf("local vulnerability scanning does not support %q", cfg.VulnScan.DependencySource)
		}
		for _, target := range targets {
			if _, err := localexec.Resolve(target.path, cfg.VulnScan.DependencySource, resolve); err != nil {
				return fmt.Errorf("requested vulnerability scanner %q is unavailable or untrusted: %w", cfg.VulnScan.DependencySource, err)
			}
		}
	}
	return nil
}

func scanOneTarget(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, policyIdentity updatesnapshot.PolicyIdentity, minAge time.Duration) scanResult {
	result := scanResult{
		Project: target.name, Directory: target.path, Origin: target.origin, Execution: options.execution,
		Status: "clean", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Warnings: []string{},
	}
	if options.only == "packages" {
		result.Tools = append(result.Tools, scanToolResult{Name: "vulnerabilities", Status: "skipped", Reason: "not requested"})
	} else {
		findings, err := scanVulnerabilities(ctx, cfg, target, options.execution)
		if err != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: cfg.VulnScan.DependencySource, Status: "failed", Reason: err.Error()})
			if options.only == "" {
				result.Tools = append(result.Tools, scanToolResult{Name: "package-manager", Status: "skipped", Reason: "vulnerability scan failed"})
			}
			return failedScanResult(result, "vulnerability_scan_failed", err, "Make the configured scanner available and run scan again")
		}
		result.Vulnerabilities = findings
		result.Tools = append(result.Tools, scanToolResult{Name: cfg.VulnScan.DependencySource, Status: "used"})
	}
	if options.only == "vulnerabilities" {
		result.Tools = append(result.Tools, scanToolResult{Name: "package-manager", Status: "skipped", Reason: "not requested"})
		return result
	}

	candidates, inputHashes, manager, verified, err := scanPackages(ctx, cfg, target, options, policy, minAge)
	if err != nil {
		result.Tools = append(result.Tools, scanToolResult{Name: manager, Status: "failed", Reason: err.Error()})
		return failedScanResult(result, "package_scan_failed", err, "Review the package-manager and execution-mode diagnostics")
	}
	unverified := false
	for index := range candidates {
		candidates[index].ReleaseAgeVerified = minAge == 0 || (verified && candidates[index].Kind != "docker")
		unverified = unverified || !candidates[index].ReleaseAgeVerified
	}
	result.Candidates = filterPolicyCandidates(candidates, policy.AllowedPackages)
	result.Tools = append(result.Tools, scanToolResult{Name: manager, Status: "used"})
	if minAge > 0 && unverified && len(result.Candidates) > 0 {
		result.Warnings = append(result.Warnings, "release age could not be verified for one or more candidates; update must fail closed unless explicitly authorized")
	}
	if options.allowProjectConfig {
		result.Warnings = append(result.Warnings, "reviewed project package-manager configuration was allowed during scan")
	}
	if len(result.Candidates) == 0 {
		return result
	}

	configHash := "adhoc"
	if target.workspace != nil {
		configHash, err = cfg.SnapshotPolicyHash(*target.workspace)
		if err != nil {
			return failedScanResult(result, "snapshot_failed", err, "Validate the project configuration")
		}
	}
	gates := updatesnapshot.ScanGates{AllowProjectConfig: options.allowProjectConfig, MinReleaseAge: minAge.String()}
	effectiveHash, err := effectiveScanPolicyHash(configHash, policyIdentity, gates)
	if err != nil {
		return failedScanResult(result, "snapshot_failed", err, "Run scan again")
	}
	var snapshot updatesnapshot.Snapshot
	if target.workspace != nil {
		identity, identityErr := scanner.IdentityForSnapshot(ctx, *target.workspace)
		if identityErr != nil {
			return failedScanResult(result, "snapshot_failed", identityErr, "Commit or stash changes, then run scan again")
		}
		snapshot, err = updatesnapshot.NewWorkspace(time.Now(), cfg.SnapshotTTL(), target.name, updatesnapshot.WorkspaceIdentity{
			CanonicalPath: identity.CanonicalPath, Remote: identity.Remote, BaseRevision: identity.BaseRevision, InputHashes: identity.InputHashes,
		}, policyIdentity, gates, configHash, effectiveHash, result.Candidates)
	} else {
		snapshot, err = updatesnapshot.NewAdhoc(time.Now(), cfg.SnapshotTTL(), target.path, inputHashes, policyIdentity, gates, effectiveHash, result.Candidates)
	}
	if err != nil {
		return failedScanResult(result, "snapshot_failed", err, "Run scan again")
	}
	stateDir, err := cfg.SnapshotStateDir()
	if err != nil {
		return failedScanResult(result, "snapshot_failed", err, "Set a valid snapshot state directory")
	}
	if err := (updatesnapshot.Store{Dir: stateDir}).Save(snapshot); err != nil {
		return failedScanResult(result, "snapshot_failed", err, "Check snapshot state-directory permissions")
	}
	result.SnapshotID = snapshot.ID
	result.Status = "ready"
	return result
}

func scanVulnerabilities(ctx context.Context, cfg config.Config, target scanTarget, execution string) ([]string, error) {
	workspace := config.Workspace{Path: target.path}
	if target.workspace != nil {
		workspace = *target.workspace
	}
	security := pipeline.DefaultSecurityGate{Scanner: vulnscan.Scanner{}, GitHub: githubalerts.Client{}}
	if execution == "local" {
		localConfig := cfg
		localConfig.VulnScan.PolicyFile = ""
		security.Scanner = vulnscan.Scanner{Command: localScannerCommand}
		cfg = localConfig
	}
	report, err := security.Baseline(ctx, workspace, cfg)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), report.Findings...), nil
}

func localScannerCommand(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	return localScannerCommandWith(nil, localexec.RunStructured)(ctx, dir, name, args...)
}

type localScannerRunner func(context.Context, string, string, []string, []string, int, int) (localexec.Result, error)

func localScannerCommandWith(resolve localexec.Resolver, run localScannerRunner) vulnscan.Command {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		binary, err := localexec.Resolve(dir, name, resolve)
		if err != nil {
			return nil, fmt.Errorf("resolve local scanner %s: %w", name, err)
		}
		environment, err := localexec.NewEnvironment()
		if err != nil {
			return nil, fmt.Errorf("prepare local scanner %s: %w", name, err)
		}

		localArgs := append([]string(nil), args...)
		for index, argument := range localArgs {
			if argument == "/project" {
				localArgs[index] = dir
			}
		}
		result, err := run(ctx, binary, dir, localArgs, environment.Variables(), localScannerStdoutMaxBytes, localScannerStderrTailMaxBytes)
		if cleanupErr := environment.Close(); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove private local-scanner state: %w", cleanupErr))
		}
		if err != nil {
			return nil, fmt.Errorf("run local %s scanner: %w: %s", name, err, strings.TrimSpace(string(result.Stderr)))
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("run local %s scanner: exit %d: %s", name, result.ExitCode, strings.TrimSpace(string(result.Stderr)))
		}
		return result.Output, nil
	}
}

func scanPackages(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, minAge time.Duration) ([]updatesnapshot.Candidate, map[string]string, string, bool, error) {
	minDays := int((minAge + 24*time.Hour - 1) / (24 * time.Hour))
	if minAge == 0 {
		minDays = 0
	}
	if target.workspace != nil {
		if err := ensureProjectConfigAllowed(target.path, target.workspace.PackageManager, options.allowProjectConfig); err != nil {
			return nil, nil, packageToolName(*target.workspace), false, err
		}
		scanConfig := cfg
		scanConfig.Update.MinReleaseAgeDays = minDays
		candidateScanner, err := updater.ResolveCandidateScanner(*target.workspace, scanConfig)
		if err != nil {
			return nil, nil, target.workspace.PackageManager, false, err
		}
		candidates, err := candidateScanner.Scan(ctx, target.path)
		return candidates, nil, packageToolName(*target.workspace), workspaceReleaseAgeVerified(*target.workspace, minAge), err
	}
	project, err := localupdate.Detect(target.path)
	if err != nil {
		return nil, nil, "package-manager", false, err
	}
	hashes, err := hashAdhocInputs(project)
	if err != nil {
		return nil, nil, project.Manager, false, err
	}
	if options.execution == "local" {
		localPolicy := policy
		localPolicy.MinReleaseAgeDays = minDays
		result, scanErr := localupdate.NewService().Scan(ctx, target.path, localPolicy, options.allowProjectConfig)
		if scanErr != nil {
			return nil, hashes, project.Manager, false, scanErr
		}
		candidates := make([]updatesnapshot.Candidate, 0, len(result.Candidates))
		for _, candidate := range result.Candidates {
			candidates = append(candidates, updatesnapshot.Candidate{Kind: project.Manager, Name: candidate.Name, Current: candidate.Current, Target: candidate.Target})
		}
		return candidates, hashes, project.Manager, result.ReleaseAgeUsed, nil
	}
	if err := ensureProjectConfigAllowed(target.path, project.Manager, options.allowProjectConfig); err != nil {
		return nil, hashes, project.Manager, false, err
	}
	workspace := workspaceForAdhoc(project)
	scanConfig := cfg
	scanConfig.Update.MinReleaseAgeDays = minDays
	candidateScanner, err := updater.ResolveCandidateScanner(workspace, scanConfig)
	if err != nil {
		return nil, hashes, project.Manager, false, err
	}
	candidates, err := candidateScanner.Scan(ctx, target.path)
	return candidates, hashes, project.Manager, workspaceReleaseAgeVerified(workspace, minAge), err
}

func ensureProjectConfigAllowed(path, manager string, allowed bool) error {
	if allowed || manager == "" {
		return nil
	}
	configs := map[string][]string{
		"npm": {".npmrc"}, "pnpm": {".npmrc", "pnpm-workspace.yaml"}, "bun": {".npmrc", "bunfig.toml"},
		"poetry": {"poetry.toml"}, "uv": {}, "pip-tools": {"pip.conf"},
	}
	for _, name := range configs[manager] {
		if _, err := os.Lstat(filepath.Join(path, name)); err == nil {
			return fmt.Errorf("%s project config %s is present; pass --allow-project-config only after reviewing registry, proxy, script-shell, and plugin settings", manager, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat project config %s: %w", name, err)
		}
	}
	return nil
}

func workspaceForAdhoc(project localupdate.Project) config.Workspace {
	stack := config.StackNode
	if project.Manager == "poetry" || project.Manager == "uv" || project.Manager == "pip-tools" {
		stack = config.StackPython
	}
	return config.Workspace{Path: project.Root, Stack: stack, PackageManager: project.Manager}
}

func packageToolName(workspace config.Workspace) string {
	if workspace.PackageManager != "" {
		return workspace.PackageManager
	}
	return "docker-registry"
}

func workspaceReleaseAgeVerified(workspace config.Workspace, minAge time.Duration) bool {
	if minAge == 0 {
		return true
	}
	return workspace.Stack == config.StackNode
}

func hashAdhocInputs(project localupdate.Project) (map[string]string, error) {
	files := []string{project.Manifest}
	if project.Lock != "" && project.Lock != project.Manifest {
		files = append(files, project.Lock)
	}
	hashes := make(map[string]string, len(files))
	for _, relative := range files {
		info, err := os.Lstat(filepath.Join(project.Root, relative))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("update input %s is not a regular file", relative)
		}
		data, err := os.ReadFile(filepath.Join(project.Root, relative))
		if err != nil {
			return nil, fmt.Errorf("read update input %s: %w", relative, err)
		}
		sum := sha256.Sum256(data)
		hashes[relative] = fmt.Sprintf("%x", sum)
	}
	return hashes, nil
}

func filterPolicyCandidates(candidates []updatesnapshot.Candidate, allowed []string) []updatesnapshot.Candidate {
	if len(allowed) == 0 {
		return candidates
	}
	allow := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allow[name] = true
	}
	filtered := make([]updatesnapshot.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Kind == "docker" || allow[candidate.Name] {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func effectiveScanPolicyHash(configHash string, policy updatesnapshot.PolicyIdentity, gates updatesnapshot.ScanGates) (string, error) {
	return updatesnapshot.EffectivePolicyHash(configHash, policy, gates)
}

func failedScanResult(result scanResult, code string, err error, hint string) scanResult {
	result.Status = "failed"
	result.Error = &jsonCommandError{Code: code, Message: err.Error(), Hint: hint}
	return result
}

func summarizeScan(results []scanResult) scanSummary {
	var summary scanSummary
	for _, result := range results {
		summary.Candidates += len(result.Candidates)
		summary.Vulnerabilities += len(result.Vulnerabilities)
		switch result.Status {
		case "failed":
			summary.Failed++
		case "ready":
			summary.Succeeded++
			summary.Ready++
		default:
			summary.Succeeded++
			summary.Clean++
		}
	}
	return summary
}

func writeHumanScanResults(results []scanResult, configFile string) {
	for _, result := range results {
		label := result.Project
		if label == "" {
			label = result.Directory
		}
		fmt.Printf("%s: %s (%d vulnerabilities, %d package candidates)\n", label, result.Status, len(result.Vulnerabilities), len(result.Candidates))
		for _, finding := range result.Vulnerabilities {
			fmt.Printf("  vulnerability: %s\n", finding)
		}
		for _, candidate := range result.Candidates {
			verification := "verified"
			if !candidate.ReleaseAgeVerified {
				verification = "unverified release age"
			}
			fmt.Printf("  %s %s: %s -> %s (%s)\n", candidate.Kind, candidate.Name, candidate.Current, candidate.Target, verification)
		}
		for _, warning := range result.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s: %s\n", label, warning)
		}
		if result.Error != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\nHint: %s\n", label, result.Error.Message, result.Error.Hint)
		}
	}
	ready := make([]scanResult, 0)
	for _, result := range results {
		if result.Status == "ready" {
			ready = append(ready, result)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool { return ready[i].Project < ready[j].Project })
	for _, result := range ready {
		defaultPath, _ := defaultConfigPath()
		if configFile != "" && configFile != defaultPath {
			fmt.Printf("Next: vuelta update --config %s %s\n", configFile, result.SnapshotID)
		} else {
			fmt.Printf("Next: vuelta update %s\n", result.SnapshotID)
		}
	}
}

func scanTopLevelFailure(jsonOutput bool, code string, err error, hint string) error {
	if jsonOutput {
		if writeErr := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "scan", Results: []scanResult{}, Summary: scanSummary{}, Warnings: []string{},
			Errors: []jsonCommandError{{Code: code, Message: err.Error(), Hint: hint}},
		}); writeErr != nil {
			return writeErr
		}
	}
	return err
}
