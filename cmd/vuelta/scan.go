package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/localexec"
	"github.com/luckyfoxdesign/vuelta/internal/localupdate"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const (
	exitEnv                        = 4
	exitFindings                   = 5
	exitPartial                    = 6
	localScannerStdoutMaxBytes     = 64 << 20
	localScannerStderrTailMaxBytes = 64 << 10
)

type scanTarget struct {
	workspace *config.Workspace
	name      string
	path      string
	origin    string
	err       error
	dockerErr error
}

type scanToolResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// stageStatus is the outcome of one independent, observable scan stage.
type stageStatus string

const (
	stageSucceeded    stageStatus = "succeeded"
	stageFailed       stageStatus = "failed"
	stageSkipped      stageStatus = "skipped"
	stageNotRequested stageStatus = "not_requested"
)

const (
	stagePreflight     = "preflight"
	stageVulnerability = "vulnerability"
	stageAlerts        = "alerts"
	stageCandidate     = "candidate"
	stageReleaseAge    = "release_age"
	stageSnapshot      = "snapshot"
)

// scanStageResult reports one independent scan stage so a failure in one
// stage never hides the outcome of another.
type scanStageResult struct {
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
	Stages          []scanStageResult          `json:"stages"`
	InputCategories []string                   `json:"input_categories"`
	Warnings        []string                   `json:"warnings"`
	Verification    []string                   `json:"verification"`
	Toolchain       *toolchain.Identity        `json:"toolchain,omitempty"`
	Error           *jsonCommandError          `json:"error,omitempty"`
}

type scanSummary struct {
	Succeeded       int `json:"succeeded"`
	Failed          int `json:"failed"`
	Partial         int `json:"partial"`
	Ready           int `json:"ready"`
	Clean           int `json:"clean"`
	Findings        int `json:"findings"`
	ScanOnly        int `json:"scan_only"`
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
	toolchainProfile   *config.ToolchainProfile
	toolchainIdentity  *toolchain.Identity
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
	targets, targetErr := resolveScanTargets(*cfg, options, currentDirectory)
	if targetErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "target_invalid", fail(exitConfig, "%v", targetErr), "Choose one of --project, --directory, or --all")
	}
	if executionErr := validateScanExecution(targets, options); executionErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "invalid_execution", fail(exitConfig, "%v", executionErr), "Use --execution container or select an unregistered --directory")
	}
	if options.execution == "container" {
		dockerErr := configureDeveloperDocker(*cfg)
		if dockerErr == nil {
			_, dockerErr = dockerexec.Default().Path()
		}
		if dockerErr != nil {
			for index := range targets {
				targets[index].dockerErr = fmt.Errorf("approved Docker endpoint is unavailable: %w", dockerErr)
			}
		}
	}
	policy, policyIdentity, policyErr := loadScanPolicy(options.policyPath)
	if policyErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "policy_invalid", fail(exitConfig, "%v", policyErr), "Review --policy and run scan again")
	}
	minAge, minAgeErr := effectiveMinReleaseAge(options.minReleaseAge, cfg.Update.MinReleaseAgeDays, policy.MinReleaseAgeDays)
	if minAgeErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "invalid_invocation", fail(exitConfig, "%v", minAgeErr), "Use 0, a Go duration such as 168h, or a day duration such as 7d")
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
	if summary.Failed > 0 && summary.Succeeded == 0 && summary.Partial == 0 {
		return fail(exitFailure, "%d scan target(s) failed", summary.Failed)
	}
	if summary.Failed > 0 || summary.Partial > 0 {
		return fail(exitPartial, "%d scan target(s) returned partial results and %d failed", summary.Partial, summary.Failed)
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
		workspace := &cfg.Workspaces[index]
		name := config.WorkspaceName(*workspace)
		canonical, err := canonicalDirectory(cfg.Workspaces[index].Path)
		if err != nil {
			registered = append(registered, scanTarget{workspace: workspace, name: name, path: workspace.Path, origin: updatesnapshot.OriginWorkspace, err: fmt.Errorf("canonicalize project %q: %w", name, err)})
			continue
		}
		registered = append(registered, scanTarget{workspace: workspace, name: name, path: canonical, origin: updatesnapshot.OriginWorkspace})
	}
	if options.all {
		if len(registered) == 0 {
			return nil, errors.New("--all requires at least one configured project")
		}
		return registered, nil
	}
	if options.project != "" {
		var matches []scanTarget
		for _, target := range registered {
			if target.name == options.project {
				matches = append(matches, target)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("project %q is not configured", options.project)
		case 1:
			return matches, nil
		default:
			return nil, fmt.Errorf("project %q is configured more than once; give every workspace a unique name", options.project)
		}
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
		if target.err != nil {
			continue
		}
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

func scanOneTarget(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, policyIdentity updatesnapshot.PolicyIdentity, minAge time.Duration) scanResult {
	return scanOneTargetWith(ctx, cfg, target, options, policy, policyIdentity, minAge, scanStageRunners{
		vulnerabilities: scanVulnerabilityStage,
		alerts:          scanAlertsStage,
		packages:        scanPackages,
		prepareToolchain: func(ctx context.Context, cfg config.Config, workspace config.Workspace) (toolchain.Prepared, error) {
			return toolchain.Prepare(ctx, workspace, cfg, dockerexec.Default(), func(message string) {
				fmt.Fprintln(os.Stderr, "toolchain:", message)
			})
		},
	})
}

type scanStageRunners struct {
	vulnerabilities  func(context.Context, config.Config, scanTarget, string) ([]string, string, bool, error)
	alerts           func(context.Context, config.Config, scanTarget) ([]string, bool, error)
	packages         func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error)
	prepareToolchain func(context.Context, config.Config, config.Workspace) (toolchain.Prepared, error)
}

func scanOneTargetWith(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, policyIdentity updatesnapshot.PolicyIdentity, minAge time.Duration, runners scanStageRunners) scanResult {
	result := scanResult{
		Project: target.name, Directory: target.path, Origin: target.origin, Execution: options.execution,
		Status: "clean", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{}, Tools: []scanToolResult{}, Stages: []scanStageResult{}, InputCategories: []string{}, Warnings: []string{}, Verification: []string{},
	}
	if target.err != nil {
		result = recordScanStageFailure(result, stagePreflight, "target_unavailable", target.err, "Fix the configured workspace path, then run scan again")
		result = addStage(result, stageVulnerability, stageNotRequested, "workspace path is unavailable")
		result = addStage(result, stageAlerts, stageNotRequested, "workspace path is unavailable")
		result = addStage(result, stageCandidate, stageNotRequested, "workspace path is unavailable")
		result = addStage(result, stageReleaseAge, stageNotRequested, "workspace path is unavailable")
		result = addStage(result, stageSnapshot, stageNotRequested, "workspace path is unavailable")
		return finalizeStageOutcomes(result)
	}
	if target.workspace != nil {
		result.Verification = config.VerificationPlan(*target.workspace)
		if target.workspace.Verification.State == config.VerificationScanOnly {
			result.Status = config.VerificationScanOnly
			result.Warnings = append(result.Warnings, "updates and update --dry-run are disabled until a ready verification profile is configured")
		}
	}
	identityConfig := cfg
	var identityWorkspace config.Workspace
	if target.workspace != nil {
		identityWorkspace = *target.workspace
	} else {
		project, detectErr := localupdate.Detect(target.path)
		if detectErr != nil {
			result = recordScanStageFailure(result, stagePreflight, "scan_input_invalid", detectErr, "Select a directory with one supported manifest/lock pair")
			result = addStage(result, stageVulnerability, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageAlerts, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageCandidate, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageReleaseAge, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageSnapshot, stageNotRequested, "project stack was not detected")
			return finalizeStageOutcomes(result)
		}
		identityWorkspace = workspaceForAdhoc(project)
		if options.execution == "local" {
			identityConfig.VulnScan.PolicyFile = ""
		}
	}
	identityOptions := workspaceIdentityOptions(identityWorkspace, identityConfig, options)
	initialInput, inputCategories, initialInputErr := adhocInputIdentityAndCategories(ctx, identityWorkspace, identityOptions)
	if initialInputErr == nil {
		result.InputCategories = inputCategories
	}
	result = addStage(result, stagePreflight, stageSucceeded, "")

	if options.only == "packages" {
		result.Tools = append(result.Tools, scanToolResult{Name: "vulnerabilities", Status: "skipped", Reason: "not requested"})
		result = addStage(result, stageVulnerability, stageNotRequested, "")
		result = addStage(result, stageAlerts, stageNotRequested, "")
	} else {
		var findings []string
		tool := cfg.VulnScan.DependencySource
		requested := true
		var scanErr error
		if target.dockerErr != nil && vulnerabilityStageUsesDocker(cfg, identityWorkspace, options.execution) {
			scanErr = target.dockerErr
		} else {
			findings, tool, requested, scanErr = runners.vulnerabilities(ctx, cfg, target, options.execution)
		}
		if !requested {
			result = addStage(result, stageVulnerability, stageNotRequested, "")
		} else if scanErr != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: tool, Status: "failed", Reason: scanErr.Error()})
			result = recordScanStageFailure(result, stageVulnerability, "vulnerability_scan_failed", scanErr, "Make the configured scanner available and run scan again")
		} else {
			result.Vulnerabilities = appendUniqueStrings(result.Vulnerabilities, findings...)
			result.Tools = append(result.Tools, scanToolResult{Name: tool, Status: "used"})
			result = addStage(result, stageVulnerability, stageSucceeded, "")
		}

		alertFindings, requested, alertErr := runners.alerts(ctx, cfg, target)
		if !requested {
			result = addStage(result, stageAlerts, stageNotRequested, "")
		} else if alertErr != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: "github-dependabot", Status: "failed", Reason: alertErr.Error()})
			result = recordScanStageFailure(result, stageAlerts, "alerts_scan_failed", alertErr, "Check the GitHub remote, token configuration, and API availability")
		} else {
			result.Vulnerabilities = appendUniqueStrings(result.Vulnerabilities, alertFindings...)
			result.Tools = append(result.Tools, scanToolResult{Name: "github-dependabot", Status: "used"})
			result = addStage(result, stageAlerts, stageSucceeded, "")
		}
	}
	if options.only == "vulnerabilities" {
		result.Tools = append(result.Tools, scanToolResult{Name: "package-manager", Status: "skipped", Reason: "not requested"})
		result = addStage(result, stageCandidate, stageNotRequested, "")
		result = addStage(result, stageReleaseAge, stageNotRequested, "")
		result = addStage(result, stageSnapshot, stageNotRequested, "")
		return finalizeStageOutcomes(result)
	}

	if options.execution == "container" && identityWorkspace.PackageManager != "" && target.dockerErr == nil && runners.prepareToolchain != nil {
		prepared, prepareErr := runners.prepareToolchain(ctx, cfg, identityWorkspace)
		if prepareErr != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: packageToolName(identityWorkspace), Status: "failed", Reason: prepareErr.Error()})
			result = recordScanStageFailure(result, stageCandidate, "toolchain_incompatible", prepareErr, "Adjust the detected runtime/manager constraint or add a compatible update.toolchain_profiles override")
			result = addStage(result, stageReleaseAge, stageNotRequested, "package candidates are unavailable")
			result = addStage(result, stageSnapshot, stageNotRequested, "package candidates are unavailable")
			return finalizeStageOutcomes(result)
		}
		options.toolchainProfile = &prepared.Profile
		options.toolchainIdentity = &prepared.Identity
		result.Toolchain = &prepared.Identity
		if prepared.Built {
			result.Warnings = append(result.Warnings, fmt.Sprintf("built default toolchain %s locally; cache key %s will be reused by later scans", prepared.Profile.ID, prepared.CacheKey[:12]))
		}
	}

	var candidates []updatesnapshot.Candidate
	manager := packageToolName(identityWorkspace)
	var verified bool
	var err error
	if target.dockerErr != nil && options.execution == "container" {
		err = target.dockerErr
	} else {
		candidates, manager, verified, err = runners.packages(ctx, cfg, target, options, policy, minAge)
	}
	if err != nil {
		result.Tools = append(result.Tools, scanToolResult{Name: manager, Status: "failed", Reason: err.Error()})
		result = recordScanStageFailure(result, stageCandidate, "package_scan_failed", err, "Review the package-manager and execution-mode diagnostics")
		result = addStage(result, stageReleaseAge, stageNotRequested, "package candidates are unavailable")
		result = addStage(result, stageSnapshot, stageNotRequested, "package candidates are unavailable")
		return finalizeStageOutcomes(result)
	}
	unverified := false
	for index := range candidates {
		candidates[index].ReleaseAgeVerified = minAge == 0 || (verified && candidates[index].Kind != "docker")
		unverified = unverified || !candidates[index].ReleaseAgeVerified
	}
	result.Candidates = filterPolicyCandidates(candidates, policy.AllowedPackages)
	result.Tools = append(result.Tools, scanToolResult{Name: manager, Status: "used"})
	result = addStage(result, stageCandidate, stageSucceeded, "")
	switch {
	case minAge == 0:
		result = addStage(result, stageReleaseAge, stageNotRequested, "")
	case unverified && len(result.Candidates) > 0:
		result.Warnings = append(result.Warnings, "release age could not be verified for one or more candidates; update must fail closed unless explicitly authorized")
		result = addStage(result, stageReleaseAge, stageSkipped, "release age could not be verified for one or more candidates")
	default:
		result = addStage(result, stageReleaseAge, stageSucceeded, "")
	}
	if options.allowProjectConfig {
		result.Warnings = append(result.Warnings, "reviewed project package-manager configuration was allowed during scan")
	}
	if len(result.Candidates) == 0 {
		result = addStage(result, stageSnapshot, stageSkipped, "no package candidates")
		return finalizeStageOutcomes(result)
	}
	if target.workspace != nil && target.workspace.Verification.State == config.VerificationScanOnly {
		result = addStage(result, stageSnapshot, stageSkipped, "verification profile is scan-only")
		return finalizeStageOutcomes(result)
	}
	if hasFailedStage(result, stageVulnerability) || hasFailedStage(result, stageAlerts) {
		result = addStage(result, stageSnapshot, stageSkipped, "a requested security stage did not complete")
		return finalizeStageOutcomes(result)
	}
	if err := validateSnapshotReadiness(cfg, target); err != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Run vuelta config validate and fix update-only configuration before creating a snapshot")
		return finalizeStageOutcomes(result)
	}
	if initialInputErr != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", initialInputErr, "Review the explicit scan inputs and their limits")
		return finalizeStageOutcomes(result)
	}

	var selectedToolchain toolchain.Identity
	if options.execution == "container" && options.toolchainIdentity != nil {
		selectedToolchain = *options.toolchainIdentity
		result.Toolchain = options.toolchainIdentity
	} else if options.execution == "container" && identityWorkspace.PackageManager != "" && len(cfg.Update.ToolchainProfiles) > 0 {
		_, identity, resolveErr := updater.ResolveToolchainProfile(identityWorkspace, cfg)
		if resolveErr != nil {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", resolveErr, "Fix the selected toolchain profile before creating an update snapshot")
			return finalizeStageOutcomes(result)
		}
		selectedToolchain = *identity
		result.Toolchain = identity
	}
	configHash := "adhoc"
	verificationHash := ""
	if target.workspace != nil {
		configHash, err = cfg.SnapshotPolicyHash(*target.workspace)
		if err != nil {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Validate the project configuration")
			return finalizeStageOutcomes(result)
		}
		verificationHash, err = config.VerificationProfileHash(*target.workspace)
		if err != nil {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Validate the verification profile")
			return finalizeStageOutcomes(result)
		}
	}
	gates := updatesnapshot.ScanGates{AllowProjectConfig: options.allowProjectConfig, MinReleaseAge: minAge.String()}
	effectiveHash, err := effectiveScanPolicyHash(configHash, policyIdentity, gates)
	if err != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Run scan again")
		return finalizeStageOutcomes(result)
	}
	var snapshot updatesnapshot.Snapshot
	if target.workspace != nil {
		identity, identityErr := scanner.IdentityForSnapshotWithOptions(ctx, *target.workspace, identityOptions)
		if identityErr != nil {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", identityErr, "Commit or stash changes to create an update snapshot; scan findings above remain valid")
			return finalizeStageOutcomes(result)
		}
		strictInput := updatesnapshot.InputIdentity{Stages: identity.InputStages, ManifestHash: identity.InputManifestHash, Hashes: identity.InputHashes}
		if !reflect.DeepEqual(initialInput, strictInput) {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", updatesnapshot.ErrStale, "Scan inputs changed during the scan; run scan again")
			return finalizeStageOutcomes(result)
		}
		snapshot, err = updatesnapshot.NewWorkspace(time.Now(), cfg.SnapshotTTL(), target.name, updatesnapshot.WorkspaceIdentity{
			CanonicalPath: identity.CanonicalPath, Remote: identity.Remote, BaseRevision: identity.BaseRevision,
			Input: updatesnapshot.InputIdentity{Stages: identity.InputStages, ManifestHash: identity.InputManifestHash, Hashes: identity.InputHashes},
		}, policyIdentity, gates, configHash, verificationHash, selectedToolchain, effectiveHash, result.Candidates)
	} else {
		identity, identityErr := adhocInputIdentity(ctx, identityWorkspace, identityOptions)
		if identityErr != nil {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", identityErr, "Restore the explicit scan inputs and run scan again")
			return finalizeStageOutcomes(result)
		}
		if !reflect.DeepEqual(initialInput, identity) {
			result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", updatesnapshot.ErrStale, "Scan inputs changed during the scan; run scan again")
			return finalizeStageOutcomes(result)
		}
		snapshot, err = updatesnapshot.NewAdhoc(time.Now(), cfg.SnapshotTTL(), target.path, identity, policyIdentity, gates, effectiveHash, result.Candidates)
	}
	if err != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Run scan again")
		return finalizeStageOutcomes(result)
	}
	stateDir, err := cfg.SnapshotStateDir()
	if err != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Set a valid snapshot state directory")
		return finalizeStageOutcomes(result)
	}
	if err := (updatesnapshot.Store{Dir: stateDir}).Save(snapshot); err != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Check snapshot state-directory permissions")
		return finalizeStageOutcomes(result)
	}
	result.SnapshotID = snapshot.ID
	result.Status = "ready"
	result = addStage(result, stageSnapshot, stageSucceeded, "")
	return result
}

// addStage records one independent stage outcome. Stages are additive and
// never overwritten, so a later failure never hides an earlier success.
func addStage(result scanResult, name string, status stageStatus, reason string) scanResult {
	result.Stages = append(result.Stages, scanStageResult{Name: name, Status: string(status), Reason: reason})
	return result
}

// hasSucceededDataStage reports whether an independent stage that produces
// user-visible findings (vulnerabilities or package candidates) already
// completed successfully before a later stage failed.
func hasSucceededDataStage(result scanResult) bool {
	for _, stage := range result.Stages {
		if stage.Status == string(stageSucceeded) && (stage.Name == stageVulnerability || stage.Name == stageAlerts || stage.Name == stageCandidate) {
			return true
		}
	}
	return false
}

func hasFailedStage(result scanResult, name string) bool {
	for _, stage := range result.Stages {
		if stage.Name == name && stage.Status == string(stageFailed) {
			return true
		}
	}
	return false
}

func finalizeStageOutcomes(result scanResult) scanResult {
	hasFailure := false
	for _, stage := range result.Stages {
		if stage.Status == string(stageFailed) {
			hasFailure = true
			break
		}
	}
	if !hasFailure {
		return finalizeCleanOrFindings(result)
	}
	if hasSucceededDataStage(result) || (result.Error != nil && result.Error.Code == "toolchain_incompatible") {
		result.Status = "partial"
	} else {
		result.Status = "failed"
	}
	return result
}

// finalizeCleanOrFindings promotes the default "clean" status to "findings"
// once vulnerabilities or candidates are present, so a target with real
// findings can never report as clean. It leaves an already-explicit status
// (for example scan-only verification) untouched.
func finalizeCleanOrFindings(result scanResult) scanResult {
	if result.Status != "clean" {
		return result
	}
	if len(result.Vulnerabilities) > 0 || len(result.Candidates) > 0 {
		result.Status = "findings"
	}
	return result
}

func scanVulnerabilityStage(ctx context.Context, cfg config.Config, target scanTarget, execution string) ([]string, string, bool, error) {
	workspace, err := scanWorkspace(target)
	if err != nil {
		return nil, cfg.VulnScan.DependencySource, true, err
	}
	scanner := vulnscan.NewReadOnlyScanner()
	if execution == "local" {
		localConfig := cfg
		localConfig.VulnScan.PolicyFile = ""
		cfg = localConfig
		scanner = vulnscan.NewAdhocScanner(localScannerCommand)
	}
	if cfg.VulnScan.DependencySource == "github-dependabot" {
		if !cfg.VulnScan.ImageScan.Enabled || workspace.DockerImages == nil {
			return nil, "trivy-images", false, nil
		}
		report, scanErr := scanner.ScanImages(ctx, target.path, workspace, cfg)
		return findingRefs(report.Findings), cfg.VulnScan.ImageScan.Tool, true, scanErr
	}
	report, scanErr := scanner.Scan(ctx, target.path, workspace, cfg)
	return findingRefs(report.Findings), cfg.VulnScan.DependencySource, true, scanErr
}

func vulnerabilityStageUsesDocker(cfg config.Config, workspace config.Workspace, execution string) bool {
	if execution != "container" {
		return false
	}
	if cfg.VulnScan.DependencySource == "github-dependabot" {
		return cfg.VulnScan.ImageScan.Enabled && workspace.DockerImages != nil
	}
	return true
}

func scanAlertsStage(ctx context.Context, cfg config.Config, target scanTarget) ([]string, bool, error) {
	if cfg.VulnScan.DependencySource != "github-dependabot" {
		return nil, false, nil
	}
	workspace, err := scanWorkspace(target)
	if err != nil {
		return nil, true, err
	}
	findings, err := (githubalerts.Client{}).Scan(ctx, workspace, cfg.GithubAdvisories)
	return findingRefs(findings), true, err
}

func scanWorkspace(target scanTarget) (config.Workspace, error) {
	if target.workspace != nil {
		return *target.workspace, nil
	}
	project, err := localupdate.Detect(target.path)
	if err != nil {
		return config.Workspace{}, err
	}
	return workspaceForAdhoc(project), nil
}

func findingRefs(findings []vulnscan.Finding) []string {
	refs := make([]string, 0, len(findings))
	for _, finding := range findings {
		refs = appendUniqueStrings(refs, finding.Ref())
	}
	sort.Strings(refs)
	return refs
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
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
			category, detail := localexec.Classify(err, result)
			return nil, &localScanError{tool: name, category: category, exitCode: -1, detail: detail, err: err}
		}
		if result.ExitCode != 0 {
			category, detail := localexec.Classify(nil, result)
			return nil, &localScanError{tool: name, category: category, exitCode: result.ExitCode, detail: detail}
		}
		return result.Output, nil
	}
}

// localScanError reports a local-tool scanner failure without embedding raw,
// unbounded, or unredacted subprocess output in its top-level message. The
// safe category/exit code/bounded detail are recovered via
// classifySubprocessError.
type localScanError struct {
	tool     string
	category safeerr.Category
	exitCode int
	detail   string
	err      error
}

func (e *localScanError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("run local %s scanner failed", e.tool)
	}
	return fmt.Sprintf("local %s scanner exited %d", e.tool, e.exitCode)
}

func (e *localScanError) Unwrap() error { return e.err }

func scanPackages(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, minAge time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
	minDays := int((minAge + 24*time.Hour - 1) / (24 * time.Hour))
	if minAge == 0 {
		minDays = 0
	}
	if target.workspace != nil {
		scanConfig := cfg
		scanConfig.Update.MinReleaseAgeDays = minDays
		failOpenUnsupportedReleaseAge(&scanConfig, *target.workspace, options.toolchainIdentity)
		candidateScanner, err := updater.ResolveCandidateScannerWithOptions(*target.workspace, scanConfig, updater.CandidateScannerOptions{
			AllowProjectConfig: options.allowProjectConfig, RequireTracked: false, ToolchainProfile: options.toolchainProfile,
		})
		if err != nil {
			return nil, target.workspace.PackageManager, false, err
		}
		candidates, err := candidateScanner.Scan(ctx, target.path)
		return candidates, packageToolName(*target.workspace), workspaceReleaseAgeVerified(*target.workspace, cfg, minAge, options.toolchainIdentity), err
	}
	project, err := localupdate.Detect(target.path)
	if err != nil {
		return nil, "package-manager", false, err
	}
	if options.execution == "local" {
		localPolicy := policy
		localPolicy.MinReleaseAgeDays = minDays
		result, scanErr := localupdate.NewService().Scan(ctx, target.path, localPolicy, options.allowProjectConfig)
		if scanErr != nil {
			return nil, project.Manager, false, scanErr
		}
		candidates := make([]updatesnapshot.Candidate, 0, len(result.Candidates))
		for _, candidate := range result.Candidates {
			candidates = append(candidates, updatesnapshot.Candidate{Kind: project.Manager, Name: candidate.Name, Current: candidate.Current, Target: candidate.Target})
		}
		return candidates, project.Manager, result.ReleaseAgeUsed, nil
	}
	workspace := workspaceForAdhoc(project)
	scanConfig := cfg
	scanConfig.Update.MinReleaseAgeDays = minDays
	failOpenUnsupportedReleaseAge(&scanConfig, workspace, options.toolchainIdentity)
	candidateScanner, err := updater.ResolveCandidateScannerWithOptions(workspace, scanConfig, updater.CandidateScannerOptions{
		AllowProjectConfig: options.allowProjectConfig, RequireTracked: false, ToolchainProfile: options.toolchainProfile,
	})
	if err != nil {
		return nil, project.Manager, false, err
	}
	candidates, err := candidateScanner.Scan(ctx, target.path)
	return candidates, project.Manager, workspaceReleaseAgeVerified(workspace, cfg, minAge, options.toolchainIdentity), err
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

func workspaceReleaseAgeVerified(workspace config.Workspace, cfg config.Config, minAge time.Duration, identity *toolchain.Identity) bool {
	if minAge == 0 {
		return true
	}
	if identity != nil {
		return identity.Capabilities.ReleaseAge
	}
	if _, identity, err := updater.ResolveToolchainProfile(workspace, cfg); err == nil && identity != nil {
		return identity.Capabilities.ReleaseAge
	}
	return workspace.Stack == config.StackNode
}

func failOpenUnsupportedReleaseAge(cfg *config.Config, workspace config.Workspace, identity *toolchain.Identity) {
	if cfg.Update.MinReleaseAgeDays == 0 {
		return
	}
	if identity != nil {
		if !identity.Capabilities.ReleaseAge {
			cfg.Update.MinReleaseAgeDays = 0
		}
		return
	}
	_, identity, err := updater.ResolveToolchainProfile(workspace, *cfg)
	if err == nil && identity != nil && !identity.Capabilities.ReleaseAge {
		cfg.Update.MinReleaseAgeDays = 0
	}
}

func adhocInputIdentity(ctx context.Context, workspace config.Workspace, options scanner.IdentityOptions) (updatesnapshot.InputIdentity, error) {
	identity, _, err := adhocInputIdentityAndCategories(ctx, workspace, options)
	return identity, err
}

func adhocInputIdentityAndCategories(ctx context.Context, workspace config.Workspace, options scanner.IdentityOptions) (updatesnapshot.InputIdentity, []string, error) {
	contracts, stages, err := scanner.InputContracts(workspace, options)
	if err != nil {
		return updatesnapshot.InputIdentity{}, nil, err
	}
	manifests := make([]scaninput.Manifest, 0, len(contracts))
	for _, contract := range contracts {
		bundle, buildErr := scaninput.Build(ctx, workspace.Path, workspace.Path, scaninput.Options{}, contract)
		if buildErr != nil {
			return updatesnapshot.InputIdentity{}, nil, buildErr
		}
		manifests = append(manifests, bundle.Manifest)
		bundle.Destroy()
	}
	manifest, err := scaninput.Combine(manifests...)
	if err != nil {
		return updatesnapshot.InputIdentity{}, nil, err
	}
	stageNames := make([]string, 0, len(stages))
	for _, stage := range stages {
		stageNames = append(stageNames, string(stage))
	}
	return updatesnapshot.InputIdentity{Stages: stageNames, ManifestHash: manifest.Hash, Hashes: manifest.InputHashes}, scaninput.ManifestCategories(manifest), nil
}

func workspaceIdentityOptions(ws config.Workspace, cfg config.Config, options scanOptions) scanner.IdentityOptions {
	stages := make([]scaninput.Stage, 0, 4)
	seen := make(map[scaninput.Stage]bool)
	add := func(stage scaninput.Stage) {
		if !seen[stage] {
			seen[stage] = true
			stages = append(stages, stage)
		}
	}
	if options.only != "vulnerabilities" {
		if ws.PackageManager != "" {
			add(scaninput.StagePackageCandidates)
		}
		if ws.DockerImages != nil {
			add(scaninput.StageDockerManifest)
		}
	}
	if options.only != "packages" {
		if cfg.VulnScan.DependencySource == "trivy" || cfg.VulnScan.DependencySource == "osv-scanner" {
			add(scaninput.StageDependencyCVE)
		}
		if cfg.VulnScan.ImageScan.Enabled && ws.DockerImages != nil {
			add(scaninput.StageDockerManifest)
		}
		if cfg.VulnScan.PolicyFile != "" {
			add(scaninput.StagePolicy)
		}
	}
	return scanner.IdentityOptions{Stages: stages, AllowProjectConfig: options.allowProjectConfig, PolicyFile: cfg.VulnScan.PolicyFile}
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

func validateSnapshotReadiness(cfg config.Config, target scanTarget) error {
	selected := cfg
	if target.workspace == nil {
		selected.Workspaces = nil
	} else {
		selected.Workspaces = []config.Workspace{*target.workspace}
	}
	if err := selected.Validate(); err != nil {
		return err
	}
	return validateVerificationPolicies(selected)
}

// failedScanResult records a stage failure. Data an earlier, independent
// stage already produced (vulnerabilities or package candidates) is never
// discarded: the target becomes "partial" rather than "failed" when that
// happened, so successful findings stay visible instead of being hidden
// behind a single opaque failure.
func failedScanResult(result scanResult, stage, code string, err error, hint string) scanResult {
	return finalizeStageOutcomes(recordScanStageFailure(result, stage, code, err, hint))
}

func recordScanStageFailure(result scanResult, stage, code string, err error, hint string) scanResult {
	result = addStage(result, stage, stageFailed, safeStageReason(err))
	category, exitCode, detail := classifySubprocessError(err)
	failure := &jsonCommandError{
		Code: code, Message: err.Error(), Hint: hint,
		Stage: stage, Category: category, ExitCode: exitCode, StderrTail: detail,
	}
	if result.Error == nil {
		result.Error = failure
	}
	warning := fmt.Sprintf("%s stage unavailable: %s", stage, safeStageReason(err))
	if category != "" {
		warning += "; category=" + category
	}
	if exitCode != nil {
		warning += fmt.Sprintf("; exit_code=%d", *exitCode)
	}
	if detail != "" {
		warning += "; detail=" + detail
	}
	if hint != "" {
		warning += ". " + hint
	}
	result.Warnings = append(result.Warnings, warning)
	return result
}

// classifySubprocessError extracts a safe category, exit code, and bounded
// redacted diagnostic tail from an error that may originate from a hardened
// dockerexec or localexec command boundary. It never inspects argv,
// environment, or unbounded output, and returns zero values when err does
// not originate from a recognized command boundary.
func classifySubprocessError(err error) (category string, exitCode *int, detail string) {
	if dockerCategory, code, dockerDetail := dockerexec.Classify(err); dockerCategory != safeerr.CategoryUnknown || dockerDetail != "" {
		return string(dockerCategory), exitCodePtr(code), dockerDetail
	}
	var localErr *localScanError
	if errors.As(err, &localErr) {
		return string(localErr.category), exitCodePtr(localErr.exitCode), localErr.detail
	}
	return "", nil, ""
}

func exitCodePtr(code int) *int {
	if code < 0 {
		return nil
	}
	return &code
}

// safeStageReason is the per-stage diagnostic string. It reuses the already
// safe top-level error message rather than any raw subprocess output.
func safeStageReason(err error) string { return err.Error() }

func summarizeScan(results []scanResult) scanSummary {
	var summary scanSummary
	for _, result := range results {
		summary.Candidates += len(result.Candidates)
		summary.Vulnerabilities += len(result.Vulnerabilities)
		switch result.Status {
		case "failed":
			summary.Failed++
		case "partial":
			summary.Partial++
		case "ready":
			summary.Succeeded++
			summary.Ready++
		case config.VerificationScanOnly:
			summary.Succeeded++
			summary.ScanOnly++
		case "findings":
			summary.Succeeded++
			summary.Findings++
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
		if len(result.Stages) > 0 {
			stages := make([]string, 0, len(result.Stages))
			for _, stage := range result.Stages {
				stages = append(stages, fmt.Sprintf("%s=%s", stage.Name, stage.Status))
			}
			fmt.Printf("  stages: %s\n", strings.Join(stages, ", "))
		}
		if len(result.InputCategories) > 0 {
			fmt.Printf("  scan inputs: %s\n", strings.Join(result.InputCategories, ", "))
		}
		for _, step := range result.Verification {
			fmt.Printf("  verification: %s\n", step)
		}
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
			if result.Error.Stage != "" {
				fmt.Fprintf(os.Stderr, "  stage: %s\n", result.Error.Stage)
			}
			if result.Error.Category != "" {
				fmt.Fprintf(os.Stderr, "  category: %s\n", result.Error.Category)
			}
			if result.Error.ExitCode != nil {
				fmt.Fprintf(os.Stderr, "  exit code: %d\n", *result.Error.ExitCode)
			}
			if result.Error.StderrTail != "" {
				fmt.Fprintf(os.Stderr, "  detail: %s\n", result.Error.StderrTail)
			}
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
			fmt.Printf("Next: vuelta update --config %s -- %s\n", configFile, result.SnapshotID)
		} else {
			fmt.Printf("Next: vuelta update -- %s\n", result.SnapshotID)
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
