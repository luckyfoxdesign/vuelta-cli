package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/adhoc"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/projectstate"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const (
	exitEnv                = 4
	exitFindings           = 5
	exitPartial            = 6
	exitImageScanRequired  = 7
)

const onboardingChangedWarning = "project onboarding changed .vuelta.yaml or .gitignore; review and commit the versioned files, then repeat the scan before updating"

type scanTarget struct {
	workspace         *config.Workspace
	name              string
	path              string
	origin            string
	err               error
	dockerErr         error
	onboardingChanged bool
}

type scanToolResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type scanCapability struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// imageDrift reports that a tier-2/3 intent resolved to a different digest
// than the previous scan of the same project recorded.
type imageDrift struct {
	PreviousDigest string `json:"previous_digest"`
	CurrentDigest  string `json:"current_digest"`
}

// imageScanRecord is the structured, always-visible outcome of one image
// scan intent: either resolved (with the tier that resolution claim rests
// on) or skipped (tier 4), never a bare warning string.
type imageScanRecord struct {
	Reference           string      `json:"reference"`
	Status              string      `json:"status"` // "resolved" | "skipped"
	Reason              string      `json:"reason,omitempty"`
	ResolvedDigest      string      `json:"resolved_digest,omitempty"`
	Platform            string      `json:"platform,omitempty"`
	Tier                int         `json:"tier,omitempty"`
	ResolvedAt          *time.Time  `json:"resolved_at,omitempty"`
	Dockerfile          string      `json:"dockerfile,omitempty"`
	BaseImageOnly       bool        `json:"base_image_only,omitempty"`
	OSPackagesInstalled bool        `json:"os_packages_installed,omitempty"`
	Drift               *imageDrift `json:"drift,omitempty"`
}

// stageStatus is the outcome of one independent, observable scan stage.
type stageStatus string

const (
	stageSucceeded    stageStatus = "succeeded"
	stageFailed       stageStatus = "failed"
	stageSkipped      stageStatus = "skipped"
	stageNotRequested stageStatus = "not_requested"
	stageVerified     stageStatus = "verified"
	stageUnverified   stageStatus = "unverified"
)

const (
	stagePreflight     = "preflight"
	stageVulnerability = "vulnerability"
	stageAlerts        = "alerts"
	stageCandidate     = "candidate"
	stageReleaseAge    = "release_age"
	stageSnapshot      = "snapshot"
	stageReport        = "report"
)

// scanStageResult reports one independent scan stage so a failure in one
// stage never hides the outcome of another.
type scanStageResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type packageUpdateAvailability struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type scanResult struct {
	Project               string                     `json:"project,omitempty"`
	Directory             string                     `json:"directory"`
	Origin                string                     `json:"origin"`
	Execution             string                     `json:"execution"`
	Status                string                     `json:"status"`
	SnapshotID            string                     `json:"snapshot_id,omitempty"`
	SnapshotCreated       *time.Time                 `json:"snapshot_created_at,omitempty"`
	SnapshotExpires       *time.Time                 `json:"snapshot_expires_at,omitempty"`
	Candidates            []updatesnapshot.Candidate `json:"candidates"`
	Vulnerabilities       []string                   `json:"vulnerabilities"`
	VulnerabilityFindings []vulnscan.Finding         `json:"-"`
	Tools                 []scanToolResult           `json:"tools"`
	Stages                []scanStageResult          `json:"stages"`
	InputCategories       []string                   `json:"input_categories"`
	Warnings              []string                   `json:"warnings"`
	Verification          []string                   `json:"verification"`
	Toolchain             *toolchain.Identity        `json:"toolchain,omitempty"`
	PackageUpdates        *packageUpdateAvailability `json:"package_updates,omitempty"`
	Diagnostics           []updater.ScanDiagnostic   `json:"diagnostics"`
	Capabilities          []scanCapability           `json:"capabilities"`
	ImageScans            []imageScanRecord          `json:"image_scans"`
	Error                 *jsonCommandError          `json:"error,omitempty"`
}

type scanSummary struct {
	Succeeded        int `json:"succeeded"`
	Failed           int `json:"failed"`
	Partial          int `json:"partial"`
	Ready            int `json:"ready"`
	Clean            int `json:"clean"`
	Findings         int `json:"findings"`
	ScanOnly         int `json:"scan_only"`
	Candidates       int `json:"candidates"`
	Vulnerabilities  int `json:"vulnerabilities"`
	ImageScanSkipped int `json:"image_scan_skipped"`
}

type scanOptions struct {
	project            string
	directory          string
	all                bool
	stack              string
	only               string
	policyPath         string
	minReleaseAge      string
	allowProjectConfig bool
	failOn             string
	requireImageScan   bool
	verbose            bool
	jsonOutput         bool
	toolchainProfile   *config.ToolchainProfile
	toolchainIdentity  *toolchain.Identity
	packageDiagnostics *[]updater.ScanDiagnostic
	explicitConfig     bool
	nonInteractive     bool
	noColor            bool
	updateConfigPath   string
}

func executeScan(args []string) error {
	options, configFile, err := parseScanOptions(args)
	if err != nil {
		return scanTopLevelFailure(options.jsonOutput || scanJSONRequested(args), "invalid_invocation", err, "Run vuelta help scan for usage")
	}
	cfg, selection, loadErr := selectScanConfiguration(options, configFile)
	if loadErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "project_config_unavailable", fail(exitConfig, "%v", loadErr), "Select a supported project with --directory or an explicit config with --config")
	}
	options.updateConfigPath = selection.Path
	if selection.Scope == "project" {
		options.updateConfigPath = selection.MachineConfig
	}
	warnings := configWarnings(cfg)
	if selection.DriftWarning != "" {
		warnings = appendUniqueStrings(warnings, selection.DriftWarning)
	}
	if selection.Scope == "project" && (cfg.Docker == nil || cfg.Docker.Developer == nil) {
		warnings = append(warnings, fmt.Sprintf(
			"machine Docker trust is not configured; run %s",
			displayCommand("environment", "bootstrap", "--socket", "/path/to/docker.sock", "--config", selection.MachineConfig),
		))
	}
	targets, targetErr := resolveScanTargets(*cfg, options, currentDirectory)
	if targetErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "target_invalid", fail(exitConfig, "%v", targetErr), "Choose one of --project, --directory, or --all")
	}
	if selection.Scope == "machine" {
		targets = onboardMachineScanTargets(targets)
	}
	if selection.OnboardingChanged && len(targets) == 1 {
		targets[0].onboardingChanged = true
	}
	for _, target := range targets {
		if target.onboardingChanged {
			warnings = appendUniqueStrings(warnings, onboardingChangedWarning)
			break
		}
	}
	dockerReady := false
	dockerErr := configureDeveloperDocker(*cfg)
	if dockerErr == nil {
		_, dockerErr = dockerexec.Default().Path()
	}
	if dockerErr != nil {
		for index := range targets {
			targets[index].dockerErr = fmt.Errorf("approved Docker endpoint is unavailable: %w", dockerErr)
		}
	} else {
		dockerReady = true
	}
	policy, policyIdentity, policyErr := loadScanPolicy(options.policyPath)
	if policyErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "policy_invalid", fail(exitConfig, "%v", policyErr), "Review --policy and run scan again")
	}
	minAge, minAgeErr := effectiveMinReleaseAge(options.minReleaseAge, cfg.Update.MinReleaseAgeDays, policy.MinReleaseAgeDays)
	if minAgeErr != nil {
		return scanTopLevelFailure(options.jsonOutput, "invalid_invocation", fail(exitConfig, "%v", minAgeErr), "Use 0, a Go duration such as 168h, or a day duration such as 7d")
	}
	ctx := context.Background()
	var egressSession *egress.Session
	if dockerReady {
		egressSession = egress.NewSession(cfg.Update.Egress, dockerexec.Default())
		ctx = egress.WithSession(ctx, egressSession)
	}
	results := make([]scanResult, 0, len(targets))
	for _, target := range targets {
		results = append(results, scanOneTarget(ctx, *cfg, target, options, policy, policyIdentity, minAge))
	}
	if egressSession != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cleanupErr := egressSession.Close(cleanupCtx)
		cancel()
		if notice := egressSession.Notice(); notice != "" {
			for index := range results {
				results[index].Warnings = appendUniqueStrings(results[index].Warnings, notice)
			}
		}
		if cleanupErr != nil {
			for index := range results {
				results[index].Warnings = appendUniqueStrings(results[index].Warnings, "managed egress cleanup failed; only Vuelta-owned invocation resources were targeted")
			}
		}
	}
	results = writeProjectScanReports(results, options, time.Now().UTC())
	summary := summarizeScan(results)
	if options.jsonOutput {
		if err := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "scan", Results: results, Summary: summary,
			Warnings: warnings, Errors: []jsonCommandError{}, Config: &selection,
		}); err != nil {
			return err
		}
	} else {
		if selection.Scope == "project" {
			if selection.Status == "created" {
				fmt.Printf("Created project config: %s\n", selection.Path)
			} else {
				fmt.Printf("Using project config: %s\n", selection.Path)
			}
			fmt.Printf("Scanning %s...\n", cfg.Workspaces[0].Path)
		}
		for _, warning := range warnings {
			fmt.Fprintln(os.Stderr, "warning:", warning)
		}
		writeHumanScanResults(results, options.updateConfigPath, options.verbose, warnings)
	}
	return scanResultError(summary, options.failOn, options.requireImageScan)
}

func scanResultError(summary scanSummary, failOn string, requireImageScan bool) error {
	if summary.Failed > 0 && summary.Succeeded == 0 && summary.Partial == 0 {
		return fail(exitFailure, "%d scan target(s) failed", summary.Failed)
	}
	if summary.Failed > 0 || summary.Partial > 0 {
		return fail(exitPartial, "%d scan target(s) returned partial results and %d failed", summary.Partial, summary.Failed)
	}
	if failOn == "vulnerabilities" && summary.Vulnerabilities > 0 {
		return fail(exitFindings, "%d vulnerability finding(s)", summary.Vulnerabilities)
	}
	if requireImageScan && summary.ImageScanSkipped > 0 {
		return fail(exitImageScanRequired, "%d image scan(s) could not resolve any digest", summary.ImageScanSkipped)
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
	fs.StringVar(&options.stack, "stack", "", "resolve first-run ambiguous stack detection: python, node, or docker")
	fs.StringVar(&options.only, "only", "", "scan only vulnerabilities or packages")
	fs.StringVar(&options.policyPath, "policy", "", "standalone package policy")
	fs.StringVar(&options.minReleaseAge, "min-release-age", "", "minimum release age")
	fs.BoolVar(&options.allowProjectConfig, "allow-project-config", false, "honor reviewed package-manager config")
	fs.StringVar(&options.failOn, "fail-on", "", "return 5 for vulnerability findings")
	fs.BoolVar(&options.requireImageScan, "require-image-scan", false, "return 7 when an image scan could not resolve any digest (tier 4)")
	fs.BoolVar(&options.verbose, "verbose", false, "show technical stages, inputs, warnings, and error details")
	fs.BoolVar(&options.jsonOutput, "json", false, "write the versioned JSON envelope")
	fs.BoolVar(&options.nonInteractive, "internal-no-input", false, "disable prompts")
	fs.BoolVar(&options.noColor, "internal-no-color", false, "disable color and progress animation")
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
	options.explicitConfig = len(fs.Args()) == 1
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

func onboardMachineScanTargets(targets []scanTarget) []scanTarget {
	for index := range targets {
		target := &targets[index]
		if target.err != nil {
			continue
		}
		ignorePath := filepath.Join(target.path, ".gitignore")
		ignorePlan, err := configinit.PlanProjectGitignore(target.path)
		if err != nil {
			target.err = err
			continue
		}
		if target.workspace == nil {
			if err := configinit.ApplyProjectOnboarding(nil, "", ignorePlan, ignorePath); err != nil {
				target.err = err
				continue
			}
			target.onboardingChanged = ignorePlan.Changed
			continue
		}
		projectPath := filepath.Join(target.path, projectConfigName)
		var project *config.ProjectConfig
		var projectPlan *configinit.EditPlan
		if _, statErr := os.Lstat(projectPath); errors.Is(statErr, os.ErrNotExist) {
			workspace := *target.workspace
			workspace.Path = "."
			workspace.ToolchainProfile = ""
			project = &config.ProjectConfig{SchemaVersion: config.CurrentSchemaVersion, Workspace: workspace}
			plan, planErr := configinit.PlanProjectConfigWrite(project, projectPath)
			if planErr != nil {
				target.err = planErr
				continue
			}
			projectPlan = &plan
		} else if statErr != nil {
			target.err = fmt.Errorf("inspect project config %s: %w", projectPath, statErr)
			continue
		} else {
			project, err = config.LoadProject(projectPath)
			if err != nil {
				target.err = err
				continue
			}
		}
		if err := configinit.ApplyProjectOnboarding(projectPlan, projectPath, ignorePlan, ignorePath); err != nil {
			target.err = err
			continue
		}
		workspace, err := project.ResolvedWorkspace(projectPath)
		if err != nil {
			target.err = err
			continue
		}
		workspace.ToolchainProfile = target.workspace.ToolchainProfile
		target.workspace = &workspace
		target.name = config.WorkspaceName(workspace)
		target.onboardingChanged = projectPlan != nil || ignorePlan.Changed
	}
	return targets
}

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
	matched, err := exactRegisteredTarget(registered, canonical)
	if err != nil {
		return nil, err
	}
	if matched != nil {
		return []scanTarget{*matched}, nil
	}
	if options.directory == "" {
		return nil, errors.New("current directory is not a registered project root\nTry: vuelta scan --directory .\n     vuelta project add .\n     vuelta scan --all")
	}
	return []scanTarget{{path: canonical, origin: updatesnapshot.OriginAdhoc}}, nil
}

func exactRegisteredTarget(targets []scanTarget, path string) (*scanTarget, error) {
	var matches []scanTarget
	for _, target := range targets {
		if target.err != nil {
			continue
		}
		if target.path == path {
			matches = append(matches, target)
		}
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("configured projects %q and %q duplicate exact target %s", matches[0].name, matches[1].name, path)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return &matches[0], nil
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
			progress := newScanProgress(scanProgressEligible(options), os.Stderr)
			prepared, err := toolchain.Prepare(ctx, workspace, cfg, dockerexec.Default(), func(message string) {
				if options.verbose {
					progress.start(fmt.Sprintf("Toolchain: %s", message))
				} else {
					progress.start("Preparing scanner for the first run...")
				}
			})
			progress.stop()
			return prepared, err
		},
	})
}

type scanStageRunners struct {
	vulnerabilities  func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error)
	alerts           func(context.Context, config.Config, scanTarget) ([]vulnscan.Finding, bool, error)
	packages         func(context.Context, config.Config, scanTarget, scanOptions, config.LocalPackagePolicy, time.Duration) ([]updatesnapshot.Candidate, string, bool, error)
	prepareToolchain func(context.Context, config.Config, config.Workspace) (toolchain.Prepared, error)
}

func scanOneTargetWith(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, policyIdentity updatesnapshot.PolicyIdentity, minAge time.Duration, runners scanStageRunners) scanResult {
	result := scanResult{
		Project: target.name, Directory: target.path, Origin: target.origin, Execution: "container",
		Status: "clean", Candidates: []updatesnapshot.Candidate{}, Vulnerabilities: []string{}, VulnerabilityFindings: []vulnscan.Finding{}, Tools: []scanToolResult{}, Stages: []scanStageResult{}, InputCategories: []string{}, Warnings: []string{}, Verification: []string{}, Diagnostics: []updater.ScanDiagnostic{}, Capabilities: []scanCapability{}, ImageScans: []imageScanRecord{},
	}
	stateStore, stateErr := updatesnapshot.ProjectStore(target.path)
	if stateErr == nil {
		var cleanupDiagnostics []string
		cleanupDiagnostics, stateErr = stateStore.CleanupExpired(time.Now())
		result.Warnings = appendUniqueStrings(result.Warnings, cleanupDiagnostics...)
	}
	if stateErr != nil {
		result.Warnings = appendUniqueStrings(result.Warnings, "project-local snapshot cleanup unavailable: "+stateErr.Error())
	}
	if target.onboardingChanged {
		result.Warnings = appendUniqueStrings(result.Warnings, onboardingChangedWarning)
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
	gitAvailable := projectHasGitMetadata(target.path)
	if gitAvailable {
		result.Capabilities = append(result.Capabilities, scanCapability{Name: "git_update_snapshot", Status: "available"})
	} else {
		result.Capabilities = append(result.Capabilities, scanCapability{
			Name: "git_update_snapshot", Status: "unavailable", Reason: "git_repository_not_found",
		})
		result.Warnings = appendUniqueStrings(result.Warnings, "Git metadata was not found; scan findings remain available but Git-bound snapshots and updates are disabled")
	}
	identityConfig := cfg
	var identityWorkspace config.Workspace
	if target.workspace != nil {
		identityWorkspace = *target.workspace
	} else {
		detectedWorkspace, detectErr := scanWorkspace(target)
		if detectErr != nil {
			result = recordScanStageFailure(result, stagePreflight, "scan_input_invalid", detectErr, "Select a directory with a supported dependency input")
			result = addStage(result, stageVulnerability, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageAlerts, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageCandidate, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageReleaseAge, stageNotRequested, "project stack was not detected")
			result = addStage(result, stageSnapshot, stageNotRequested, "project stack was not detected")
			return finalizeStageOutcomes(result)
		}
		identityWorkspace = detectedWorkspace
	}
	if scanOnlyAdapter, ok := scanOnlyWorkspaceAdapter(identityWorkspace); ok {
		identityWorkspace.Stack = scanOnlyAdapter.Key().Stack
		identityWorkspace.PackageManager = scanOnlyAdapter.Key().PackageManager
		result.Status = config.VerificationScanOnly
		result.PackageUpdates = &packageUpdateAvailability{Status: config.VerificationScanOnly, Reason: "manifest_has_no_safe_mutation_contract"}
		result.Warnings = appendUniqueStrings(result.Warnings, fmt.Sprintf("%s candidates are scan-only; the manifest does not prove dependency ownership and no update snapshot will be created", scanOnlyAdapter.Key().String()))
	}
	identityOptions := workspaceIdentityOptions(identityWorkspace, identityConfig, options)
	initialInput, inputCategories, initialInputErr := adhocInputIdentityAndCategories(ctx, identityWorkspace, identityOptions)
	if initialInputErr == nil {
		result.InputCategories = inputCategories
	}
	result = addStage(result, stagePreflight, stageSucceeded, "")
	progress := newScanProgress(scanProgressEligible(options), os.Stderr)

	if options.only == "packages" {
		result.Tools = append(result.Tools, scanToolResult{Name: "vulnerabilities", Status: "skipped", Reason: "not requested"})
		result = addStage(result, stageVulnerability, stageNotRequested, "")
		result = addStage(result, stageAlerts, stageNotRequested, "")
	} else {
		var findings []vulnscan.Finding
		var imageResolutions []vulnscan.ImageResolution
		var imageSkips []vulnscan.ImageSkip
		tool := cfg.VulnScan.DependencySource
		requested := true
		var scanErr error
		if target.dockerErr != nil && vulnerabilityStageUsesDocker(cfg, identityWorkspace) {
			scanErr = target.dockerErr
		} else {
			progress.start("Scanning for vulnerabilities...")
			findings, imageResolutions, imageSkips, tool, requested, scanErr = runners.vulnerabilities(ctx, cfg, target)
			progress.stop()
		}
		if !requested {
			result = addStage(result, stageVulnerability, stageNotRequested, "")
		} else if scanErr != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: tool, Status: "failed", Reason: scanErr.Error()})
			result = recordScanStageFailure(result, stageVulnerability, "vulnerability_scan_failed", scanErr, "Make the configured scanner available and run scan again")
		} else {
			result.VulnerabilityFindings = appendUniqueFindings(result.VulnerabilityFindings, findings...)
			result.Tools = append(result.Tools, scanToolResult{Name: tool, Status: "used"})
			result = addStage(result, stageVulnerability, stageSucceeded, "")
			imageScans, driftWarnings := buildImageScanRecords(target.path, imageResolutions, imageSkips)
			result.ImageScans = imageScans
			result.Warnings = appendUniqueStrings(result.Warnings, driftWarnings...)
		}

		progress.start("Checking GitHub security alerts...")
		alertFindings, requested, alertErr := runners.alerts(ctx, cfg, target)
		progress.stop()
		if !requested {
			result = addStage(result, stageAlerts, stageNotRequested, "")
		} else if alertErr != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: "github-dependabot", Status: "failed", Reason: alertErr.Error()})
			result = recordScanStageFailure(result, stageAlerts, "alerts_scan_failed", alertErr, "Check the GitHub remote, token configuration, and API availability")
		} else {
			result.VulnerabilityFindings = appendUniqueFindings(result.VulnerabilityFindings, alertFindings...)
			result.Tools = append(result.Tools, scanToolResult{Name: "github-dependabot", Status: "used"})
			result = addStage(result, stageAlerts, stageSucceeded, "")
		}
		sort.SliceStable(result.VulnerabilityFindings, func(i, j int) bool {
			return result.VulnerabilityFindings[i].ID < result.VulnerabilityFindings[j].ID
		})
		result.Vulnerabilities = findingRefs(result.VulnerabilityFindings)
	}
	if options.only == "vulnerabilities" {
		result.Tools = append(result.Tools, scanToolResult{Name: "package-manager", Status: "skipped", Reason: "not requested"})
		result = addStage(result, stageCandidate, stageNotRequested, "")
		result = addStage(result, stageReleaseAge, stageNotRequested, "")
		result = addStage(result, stageSnapshot, stageNotRequested, "")
		return finalizeStageOutcomes(result)
	}

	if identityWorkspace.PackageManager != "" && target.dockerErr == nil && runners.prepareToolchain != nil {
		prepared, prepareErr := runners.prepareToolchain(ctx, cfg, identityWorkspace)
		if prepareErr != nil {
			result.Tools = append(result.Tools, scanToolResult{Name: packageToolName(identityWorkspace), Status: "failed", Reason: prepareErr.Error()})
			result = recordScanStageFailure(result, stageCandidate, "toolchain_incompatible", prepareErr, "Adjust the detected runtime/manager constraint or add a compatible update.toolchain_profiles override")
			result = addUnavailableReleaseAgeStage(result, minAge, "package candidates are unavailable")
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
	var packageDiagnostics []updater.ScanDiagnostic
	options.packageDiagnostics = &packageDiagnostics
	manager := packageToolName(identityWorkspace)
	var verified bool
	var err error
	if target.dockerErr != nil {
		err = target.dockerErr
	} else {
		progress.start("Scanning packages for updates...")
		candidates, manager, verified, err = runners.packages(ctx, cfg, target, options, policy, minAge)
		progress.stop()
	}
	result.Diagnostics = append(result.Diagnostics, packageDiagnostics...)
	if err != nil {
		result.Tools = append(result.Tools, scanToolResult{Name: manager, Status: "failed", Reason: err.Error()})
		result = recordScanStageFailure(result, stageCandidate, "package_scan_failed", err, "Review the package-manager and container diagnostics")
		result = addUnavailableReleaseAgeStage(result, minAge, "package candidates are unavailable")
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
		warning := "release age could not be verified for one or more candidates; update must fail closed unless explicitly authorized"
		if workspaceScanOnly(identityWorkspace) {
			warning = "release age could not be verified for one or more scan-only candidates; they cannot be updated"
		}
		result.Warnings = append(result.Warnings, warning)
		result = addStage(result, stageReleaseAge, stageUnverified, "release age could not be verified for one or more candidates")
	default:
		result = addStage(result, stageReleaseAge, stageVerified, "")
	}
	if options.allowProjectConfig && !workspaceScanOnly(identityWorkspace) {
		result.Warnings = append(result.Warnings, "reviewed project package-manager configuration was allowed during scan")
	}
	if workspaceScanOnly(identityWorkspace) {
		result = addStage(result, stageSnapshot, stageSkipped, "manifest has no safe mutation contract")
		return finalizeStageOutcomes(result)
	}
	if len(result.Candidates) == 0 {
		result = addStage(result, stageSnapshot, stageSkipped, "no package candidates")
		return finalizeStageOutcomes(result)
	}
	if target.workspace != nil && !gitAvailable {
		result.Status = config.VerificationScanOnly
		result.PackageUpdates = &packageUpdateAvailability{Status: config.VerificationScanOnly, Reason: "git_repository_not_found"}
		result = addStage(result, stageSnapshot, stageSkipped, "git_repository_not_found")
		return finalizeStageOutcomes(result)
	}
	if target.workspace != nil && target.workspace.Verification.State == config.VerificationScanOnly {
		result = addStage(result, stageSnapshot, stageSkipped, "verification profile is scan-only")
		return finalizeStageOutcomes(result)
	}
	if target.onboardingChanged {
		result = addStage(result, stageSnapshot, stageSkipped, "project onboarding must be reviewed and committed")
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
	if options.toolchainIdentity != nil {
		selectedToolchain = *options.toolchainIdentity
		result.Toolchain = options.toolchainIdentity
	} else if identityWorkspace.PackageManager != "" && len(cfg.Update.ToolchainProfiles) > 0 {
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
	if stateErr != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", stateErr, "Review the selected project's .vuelta/snapshots directory")
		return finalizeStageOutcomes(result)
	}
	if err := stateStore.Save(snapshot); err != nil {
		result = recordScanStageFailure(result, stageSnapshot, "snapshot_failed", err, "Check the selected project's .vuelta directory permissions and file types")
		return finalizeStageOutcomes(result)
	}
	result.SnapshotID = snapshot.ID
	created, expires := snapshot.CreatedAt, snapshot.ExpiresAt
	result.SnapshotCreated = &created
	result.SnapshotExpires = &expires
	result.Status = "ready"
	result = addStage(result, stageSnapshot, stageSucceeded, "")
	return result
}

func addUnavailableReleaseAgeStage(result scanResult, minAge time.Duration, reason string) scanResult {
	if minAge > 0 {
		return addStage(result, stageReleaseAge, stageFailed, reason)
	}
	return addStage(result, stageReleaseAge, stageNotRequested, reason)
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

func scanVulnerabilityStage(ctx context.Context, cfg config.Config, target scanTarget) ([]vulnscan.Finding, []vulnscan.ImageResolution, []vulnscan.ImageSkip, string, bool, error) {
	workspace, err := scanWorkspace(target)
	if err != nil {
		return nil, nil, nil, cfg.VulnScan.DependencySource, true, err
	}
	scanner := vulnscan.NewReadOnlyScanner()
	if cfg.VulnScan.DependencySource == "github-dependabot" {
		if !cfg.VulnScan.ImageScan.Enabled || workspace.DockerImages == nil {
			return nil, nil, nil, "trivy-images", false, nil
		}
		report, scanErr := scanner.ScanImages(ctx, target.path, workspace, cfg)
		return report.Findings, report.ImageResolutions, report.ImageSkips, cfg.VulnScan.ImageScan.Tool, true, scanErr
	}
	report, scanErr := scanner.Scan(ctx, target.path, workspace, cfg)
	return report.Findings, report.ImageResolutions, report.ImageSkips, cfg.VulnScan.DependencySource, true, scanErr
}

// buildImageScanRecords turns one scan's raw image resolutions/skips into
// the structured, always-visible records the CLI reports, comparing each
// resolution against the previous scan's recorded digest to surface base
// image drift as a distinct, explicit signal.
func buildImageScanRecords(targetPath string, resolutions []vulnscan.ImageResolution, skips []vulnscan.ImageSkip) ([]imageScanRecord, []string) {
	if len(resolutions) == 0 && len(skips) == 0 {
		return nil, nil
	}
	previous := make(map[string]string)
	if state, err := projectstate.FromCanonical(targetPath); err == nil {
		if records, err := state.ReadImageScanState(); err == nil {
			for _, record := range records {
				previous[record.Reference+"\x00"+record.Platform] = record.Digest
			}
		}
	}
	var records []imageScanRecord
	var warnings []string
	for _, resolution := range resolutions {
		resolvedAt := resolution.ResolvedAt
		record := imageScanRecord{
			Reference: resolution.Reference, Status: "resolved", ResolvedDigest: resolution.ResolvedDigest,
			Platform: resolution.Platform, Tier: int(resolution.Tier), ResolvedAt: &resolvedAt, Dockerfile: resolution.Dockerfile,
			BaseImageOnly: resolution.Tier == vulnscan.TierBaseImageTag, OSPackagesInstalled: resolution.OSPackagesInstalled,
		}
		if previousDigest, ok := previous[resolution.Reference+"\x00"+resolution.Platform]; ok && previousDigest != resolution.ResolvedDigest {
			record.Drift = &imageDrift{PreviousDigest: previousDigest, CurrentDigest: resolution.ResolvedDigest}
			warnings = append(warnings, fmt.Sprintf(
				"base image drift: %s (%s) resolved to %s previously, now %s",
				resolution.Reference, resolution.Platform, previousDigest, resolution.ResolvedDigest,
			))
		}
		records = append(records, record)
	}
	for _, skip := range skips {
		records = append(records, imageScanRecord{Reference: skip.Reference, Status: "skipped", Reason: skip.Reason})
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Reference != records[j].Reference {
			return records[i].Reference < records[j].Reference
		}
		return records[i].Platform < records[j].Platform
	})
	return records, warnings
}

// persistImageScanState records this scan's resolved digests so the next
// scan of the same project can detect base image drift. Skipped (tier-4)
// intents are never persisted: there is no digest to compare against.
func persistImageScanState(target projectstate.Target, records []imageScanRecord) error {
	resolved := make([]projectstate.ImageScanRecord, 0, len(records))
	for _, record := range records {
		if record.Status != "resolved" {
			continue
		}
		resolved = append(resolved, projectstate.ImageScanRecord{
			Reference: record.Reference, Platform: record.Platform, Digest: record.ResolvedDigest,
		})
	}
	if len(resolved) == 0 {
		return nil
	}
	return target.WriteImageScanState(resolved)
}

func vulnerabilityStageUsesDocker(cfg config.Config, workspace config.Workspace) bool {
	if cfg.VulnScan.DependencySource == "github-dependabot" {
		return cfg.VulnScan.ImageScan.Enabled && workspace.DockerImages != nil
	}
	return true
}

func scanAlertsStage(ctx context.Context, cfg config.Config, target scanTarget) ([]vulnscan.Finding, bool, error) {
	if cfg.VulnScan.DependencySource != "github-dependabot" {
		return nil, false, nil
	}
	workspace, err := scanWorkspace(target)
	if err != nil {
		return nil, true, err
	}
	findings, err := (githubalerts.Client{}).Scan(ctx, workspace, cfg.GithubAdvisories)
	return findings, true, err
}

func scanWorkspace(target scanTarget) (config.Workspace, error) {
	if target.workspace != nil {
		workspace := *target.workspace
		if adapter, ok := scanOnlyWorkspaceAdapter(workspace); ok {
			workspace.Stack = adapter.Key().Stack
			workspace.PackageManager = adapter.Key().PackageManager
		}
		return workspace, nil
	}
	project, err := adhoc.Detect(target.path)
	if err == nil {
		return workspaceForAdhoc(project), nil
	}
	if adapters, discoverErr := catalog.Discover(target.path); discoverErr == nil {
		for _, adapter := range adapters {
			if _, mutable := adapter.(ecosystem.MutationProvider); !mutable && adapter.Metadata().UnsupportedReason == "" {
				return config.Workspace{
					Path: target.path, Stack: adapter.Key().Stack, PackageManager: adapter.Key().PackageManager,
				}, nil
			}
		}
	}
	return config.Workspace{}, err
}

func scanOnlyWorkspaceAdapter(workspace config.Workspace) (ecosystem.Adapter, bool) {
	if workspace.PackageManager != "" {
		registry, err := catalog.New()
		if err != nil {
			return nil, false
		}
		adapter, err := registry.Lookup(workspace.Stack, workspace.PackageManager)
		if err != nil {
			return nil, false
		}
		_, mutable := adapter.(ecosystem.MutationProvider)
		return adapter, !mutable && adapter.Metadata().UnsupportedReason == ""
	}
	adapters, err := catalog.Discover(workspace.Path)
	if err != nil || len(adapters) != 1 {
		return nil, false
	}
	_, mutable := adapters[0].(ecosystem.MutationProvider)
	return adapters[0], !mutable && adapters[0].Metadata().UnsupportedReason == ""
}

func findingRefs(findings []vulnscan.Finding) []string {
	refs := make([]string, 0, len(findings))
	for _, finding := range findings {
		refs = appendUniqueStrings(refs, finding.Ref())
	}
	sort.Strings(refs)
	return refs
}

func appendUniqueFindings(values []vulnscan.Finding, additions ...vulnscan.Finding) []vulnscan.Finding {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value.Ref()] = true
	}
	for _, value := range additions {
		if !seen[value.Ref()] {
			values = append(values, value)
			seen[value.Ref()] = true
		}
	}
	return values
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

func scanPackages(ctx context.Context, cfg config.Config, target scanTarget, options scanOptions, policy config.LocalPackagePolicy, minAge time.Duration) ([]updatesnapshot.Candidate, string, bool, error) {
	minDays := int((minAge + 24*time.Hour - 1) / (24 * time.Hour))
	if minAge == 0 {
		minDays = 0
	}
	if target.workspace != nil {
		workspace, err := scanWorkspace(target)
		if err != nil {
			return nil, "package-manager", false, err
		}
		scanConfig := cfg
		scanConfig.Update.MinReleaseAgeDays = minDays
		failOpenUnsupportedReleaseAge(&scanConfig, workspace, options.toolchainIdentity)
		candidateScanner, err := updater.ResolveCandidateScannerWithOptions(workspace, scanConfig, updater.CandidateScannerOptions{
			AllowProjectConfig: options.allowProjectConfig, RequireTracked: false, ToolchainProfile: options.toolchainProfile,
		})
		if err != nil {
			return nil, workspace.PackageManager, false, err
		}
		report, err := updater.ScanCandidateReport(ctx, candidateScanner, target.path)
		if options.packageDiagnostics != nil {
			*options.packageDiagnostics = append(*options.packageDiagnostics, report.Diagnostics...)
		}
		return report.Candidates, packageToolName(workspace), workspaceReleaseAgeVerified(workspace, cfg, minAge, options.toolchainIdentity), err
	}
	if workspace, detectErr := scanWorkspace(target); detectErr == nil && workspaceScanOnly(workspace) {
		scanConfig := cfg
		scanConfig.Update.MinReleaseAgeDays = minDays
		failOpenUnsupportedReleaseAge(&scanConfig, workspace, options.toolchainIdentity)
		candidateScanner, err := updater.ResolveCandidateScannerWithOptions(workspace, scanConfig, updater.CandidateScannerOptions{RequireTracked: false, ToolchainProfile: options.toolchainProfile})
		if err != nil {
			return nil, packageToolName(workspace), false, err
		}
		report, err := updater.ScanCandidateReport(ctx, candidateScanner, target.path)
		if options.packageDiagnostics != nil {
			*options.packageDiagnostics = append(*options.packageDiagnostics, report.Diagnostics...)
		}
		return report.Candidates, packageToolName(workspace), workspaceReleaseAgeVerified(workspace, cfg, minAge, options.toolchainIdentity), err
	}
	project, err := adhoc.Detect(target.path)
	if err != nil {
		return nil, "package-manager", false, err
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

func workspaceForAdhoc(project adhoc.Project) config.Workspace {
	return config.Workspace{Path: project.Root, Stack: project.Stack, PackageManager: project.Manager}
}

func workspaceScanOnly(workspace config.Workspace) bool {
	if workspace.PackageManager == "" {
		return false
	}
	registry, err := catalog.New()
	if err != nil {
		return false
	}
	adapter, err := registry.Lookup(workspace.Stack, workspace.PackageManager)
	if err != nil {
		return false
	}
	_, mutable := adapter.(ecosystem.MutationProvider)
	return !mutable && adapter.Metadata().UnsupportedReason == ""
}

func packageToolName(workspace config.Workspace) string {
	if workspace.PackageManager != "" {
		return workspace.PackageManager
	}
	if workspace.Stack == config.StackDocker {
		return "docker-registry"
	}
	return "package-manager"
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
	registry, err := catalog.New()
	if err != nil {
		return false
	}
	adapter, err := registry.Lookup(workspace.Stack, workspace.PackageManager)
	if err != nil {
		return false
	}
	provider, ok := adapter.(ecosystem.ScannerProvider)
	if !ok {
		return false
	}
	policy, ok := adapter.(ecosystem.ProfilePolicyProvider)
	if !ok {
		return false
	}
	spec, err := provider.Scanner(ecosystem.ScannerRequest{
		ProfileScanner:    policy.ProfilePolicy().ExpectedScanner,
		MinReleaseAgeDays: int(minAge / (24 * time.Hour)),
	})
	return err == nil && spec.ReleaseAge
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
	code, hint = scanFailureContract(code, hint, err)
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

func scanFailureContract(code, hint string, err error) (string, string) {
	if errors.Is(err, errDockerBootstrapRequired) {
		return "endpoint_bootstrap_required", "Run vuelta environment bootstrap with the reviewed local Docker socket"
	}
	var attestation *dockerexec.AttestationError
	if errors.As(err, &attestation) {
		return "daemon_attestation_failed", "Review the configured daemon identity and bootstrap the endpoint again only if the change is expected"
	}
	var egressStage *egress.StageError
	if errors.As(err, &egressStage) {
		stage := strings.ReplaceAll(egressStage.Stage, " ", "_")
		_, _, detail := dockerexec.Classify(err)
		if strings.Contains(detail, "predefined address pools have been fully subnetted") {
			return "egress_" + stage + "_failed", "Docker has no free network subnet; stop an unused Compose project in Docker Desktop, then rerun this same Vuelta scan. Vuelta did not remove any existing network"
		}
		return "egress_" + stage + "_failed", "Inspect only the Vuelta-owned proxy/network diagnostics and retry"
	}
	return code, hint
}

// classifySubprocessError extracts a safe category, exit code, and bounded
// redacted diagnostic tail from an error that may originate from the hardened
// dockerexec command boundary. It never inspects argv, environment, or
// unbounded output, and returns zero values for other errors.
func classifySubprocessError(err error) (category string, exitCode *int, detail string) {
	if dockerCategory, code, dockerDetail := dockerexec.Classify(err); dockerCategory != safeerr.CategoryUnknown || dockerDetail != "" {
		return string(dockerCategory), exitCodePtr(code), dockerDetail
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
		for _, imageScan := range result.ImageScans {
			if imageScan.Status == "skipped" {
				summary.ImageScanSkipped++
			}
		}
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

func writeHumanScanResults(results []scanResult, machineConfig string, verbose bool, alreadyWarned []string) {
	warned := make(map[string]bool, len(alreadyWarned))
	for _, warning := range alreadyWarned {
		warned[warning] = true
	}
	for resultIndex, result := range results {
		if resultIndex > 0 {
			fmt.Println()
		}
		label := result.Project
		if label == "" {
			label = result.Directory
		}
		fmt.Printf("Scan: %s\n", label)
		fmt.Println()
		writePackageCandidateTable(result)
		fmt.Printf("Result: %s\n", conciseScanSummary(result))
		if len(result.VulnerabilityFindings) > 0 {
			fmt.Println()
			writeVulnerabilityTable(result)
		}
		if result.PackageUpdates != nil && result.PackageUpdates.Reason == "manifest_has_no_safe_mutation_contract" {
			fmt.Println("Note: requirements.txt is read-only; automatic updates are unavailable.")
		}
		for _, capability := range result.Capabilities {
			if capability.Name == "git_update_snapshot" && capability.Reason == "git_repository_not_found" {
				fmt.Println("Note: Git metadata was not found; findings remain available, but Git-bound snapshots and updates are disabled.")
			}
		}
		for _, imageScan := range result.ImageScans {
			switch {
			case imageScan.Status == "skipped":
				reference := imageScan.Reference
				if reference == "" {
					reference = "(no reference detected)"
				}
				fmt.Printf("Note: image scan skipped for %s: %s\n", reference, imageScan.Reason)
			case imageScan.BaseImageOnly:
				claim := fmt.Sprintf("Note: %s was scanned as the base image for %s, not the built artifact itself.", imageScan.ResolvedDigest, imageScan.Dockerfile)
				if imageScan.OSPackagesInstalled {
					claim += " " + imageScan.Dockerfile + " installs OS packages, so this is a weaker proxy for the built artifact's OS package surface."
				}
				fmt.Println(claim)
			}
			if imageScan.Drift != nil {
				fmt.Printf("Note: base image drift for %s: previously %s, now %s.\n", imageScan.Reference, imageScan.Drift.PreviousDigest, imageScan.Drift.CurrentDigest)
			}
		}
		for _, diagnostic := range result.Diagnostics {
			fmt.Fprintf(os.Stderr, "Issue: %s:%d [%s] %s\n", diagnostic.File, diagnostic.Line, diagnostic.Code, diagnostic.Message)
		}
		if verbose {
			fmt.Println()
			fmt.Println("Details:")
			writeScanDetails(result)
		}
		if verbose {
			pending := make([]string, 0, len(result.Warnings))
			for _, warning := range result.Warnings {
				if !warned[warning] {
					pending = append(pending, warning)
				}
			}
			if len(pending) > 0 {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "Warnings:")
				for _, warning := range pending {
					fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
				}
			}
		}
		if result.Error != nil {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error.Message)
			if result.Error.Hint != "" {
				fmt.Fprintf(os.Stderr, "Hint: %s\n", result.Error.Hint)
			}
			if verbose && result.Error.Stage != "" {
				fmt.Fprintf(os.Stderr, "  stage: %s\n", result.Error.Stage)
			}
			if verbose && result.Error.Category != "" {
				fmt.Fprintf(os.Stderr, "  category: %s\n", result.Error.Category)
			}
			if verbose && result.Error.ExitCode != nil {
				fmt.Fprintf(os.Stderr, "  exit code: %d\n", *result.Error.ExitCode)
			}
			if verbose && result.Error.StderrTail != "" {
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
		args := []string{"update", "--directory", result.Directory}
		if machineConfig != "" {
			args = append(args, "--config", machineConfig)
		}
		fmt.Printf("Next: %s\n", displayCommand(args...))
	}
}

func writeProjectScanReports(results []scanResult, options scanOptions, completedAt time.Time) []scanResult {
	for index := range results {
		result := results[index]
		target, err := projectstate.FromCanonical(result.Directory)
		if err == nil {
			var report []byte
			report, err = buildProjectScanReport(result, options, completedAt)
			if err == nil {
				err = target.WriteReport(report)
			}
			if err == nil {
				err = persistImageScanState(target, result.ImageScans)
			}
		}
		if err != nil {
			result = recordScanStageFailure(result, stageReport, "report_write_failed", err, "Review the selected project's .vuelta path, ownership, and permissions")
			result = finalizeStageOutcomes(result)
		} else {
			result = addStage(result, stageReport, stageSucceeded, "")
		}
		results[index] = result
	}
	return results
}

func buildProjectScanReport(result scanResult, options scanOptions, completedAt time.Time) ([]byte, error) {
	var report strings.Builder
	report.Grow(4096)
	status := result.Status
	if status == config.VerificationScanOnly || (status != "ready" && status != "partial" && status != "failed") {
		status = "read-only"
	}
	project := result.Project
	if project == "" {
		project = filepath.Base(result.Directory)
	}
	mode := options.only
	if mode == "" {
		mode = "vulnerabilities, packages"
	}
	fmt.Fprintf(&report, "# Vuelta scan report\n\n")
	fmt.Fprintf(&report, "- Completed: `%s`\n", completedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&report, "- Status: **%s**\n", markdownValue(status))
	fmt.Fprintf(&report, "- Project: `%s`\n", markdownValue(project))
	fmt.Fprintf(&report, "- Scan modes: `%s`\n\n", markdownValue(mode))
	fmt.Fprintln(&report, "## Package and image candidates")
	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "| Manager | Name | Current | Target | Status |")
	fmt.Fprintln(&report, "|---|---|---|---|---|")
	candidateLimit := min(len(result.Candidates), 256)
	for _, candidate := range result.Candidates[:candidateLimit] {
		fmt.Fprintf(&report, "| %s | %s | %s | %s | %s |\n",
			markdownValue(candidate.Kind), markdownValue(candidate.Name), markdownValue(candidate.Current),
			markdownValue(candidate.Target), markdownValue(packageCandidateStatus(result, candidate)),
		)
	}
	if len(result.Candidates) > candidateLimit {
		fmt.Fprintf(&report, "\n_%d additional candidates omitted._\n", len(result.Candidates)-candidateLimit)
	}
	if len(result.Candidates) == 0 {
		fmt.Fprintln(&report, "| — | — | — | — | none |")
	}

	fmt.Fprintln(&report)
	fmt.Fprintf(&report, "## Vulnerabilities (%d)\n\n", len(result.Vulnerabilities))
	vulnerabilityLimit := min(len(result.Vulnerabilities), 100)
	for _, finding := range result.Vulnerabilities[:vulnerabilityLimit] {
		fmt.Fprintf(&report, "- %s\n", markdownValue(finding))
	}
	if len(result.Vulnerabilities) == 0 {
		fmt.Fprintln(&report, "- None reported.")
	} else if len(result.Vulnerabilities) > vulnerabilityLimit {
		fmt.Fprintf(&report, "- _%d additional findings omitted; full count: %d._\n", len(result.Vulnerabilities)-vulnerabilityLimit, len(result.Vulnerabilities))
	}

	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "## Warnings and blockers")
	fmt.Fprintln(&report)
	warnings := append([]string(nil), result.Warnings...)
	if result.Error != nil {
		warnings = append(warnings, result.Error.Message)
	}
	warningLimit := min(len(warnings), 50)
	for _, warning := range warnings[:warningLimit] {
		fmt.Fprintf(&report, "- %s\n", markdownValue(warning))
	}
	if len(warnings) == 0 {
		fmt.Fprintln(&report, "- None.")
	} else if len(warnings) > warningLimit {
		fmt.Fprintf(&report, "- _%d additional warnings omitted._\n", len(warnings)-warningLimit)
	}

	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "## Update snapshot")
	fmt.Fprintln(&report)
	if result.SnapshotID == "" {
		fmt.Fprintln(&report, "No authoritative update snapshot was created.")
	} else {
		fmt.Fprintf(&report, "- ID: `%s`\n", markdownValue(result.SnapshotID))
		if result.SnapshotCreated != nil {
			fmt.Fprintf(&report, "- Created: `%s`\n", result.SnapshotCreated.UTC().Format(time.RFC3339))
		}
		if result.SnapshotExpires != nil {
			fmt.Fprintf(&report, "- Expires: `%s`\n", result.SnapshotExpires.UTC().Format(time.RFC3339))
		}
		args := []string{"update", "--directory", result.Directory}
		if options.updateConfigPath != "" {
			args = append(args, "--config", options.updateConfigPath)
		}
		fmt.Fprintf(&report, "- Next: `%s`\n", markdownValueLimit(displayCommand(args...), 4096))
	}
	fmt.Fprintln(&report)
	fmt.Fprintln(&report, "> Update authority is the selected JSON snapshot in `.vuelta/snapshots/`, never this Markdown report.")
	if report.Len() > projectstate.MaxReportBytes {
		return nil, fmt.Errorf("scan report exceeds %d bytes after bounded rendering", projectstate.MaxReportBytes)
	}
	return []byte(report.String()), nil
}

func markdownValue(value string) string {
	return markdownValueLimit(value, 256)
}

func markdownValueLimit(value string, maximum int) string {
	value = strings.TrimSpace(value)
	value = reportUserinfoURL.ReplaceAllString(value, "https://[redacted]/")
	value = strings.NewReplacer(
		"\\", "\\\\", "|", "\\|", "\r", " ", "\n", " ",
		"<", "&lt;", ">", "&gt;", "[", "\\[", "]", "\\]",
		"`", "'", "*", "\\*", "_", "\\_",
	).Replace(value)
	runes := []rune(value)
	if len(runes) > maximum {
		value = string(runes[:maximum]) + "…"
	}
	if value == "" {
		return "unknown"
	}
	return value
}

var reportUserinfoURL = regexp.MustCompile(`(?i)https?://[^/\s@]+@`)

func writeTable(w io.Writer, headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, strings.Join(headers, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(table, strings.Join(row, "\t"))
	}
	_ = table.Flush()
}

func writePackageCandidateTable(result scanResult) {
	if len(result.Candidates) == 0 {
		return
	}
	fmt.Println("Packages:")
	rows := make([][]string, 0, len(result.Candidates))
	for _, candidate := range result.Candidates {
		current := candidate.Current
		if current == "" {
			current = "unknown"
		}
		rows = append(rows, []string{
			candidate.Kind, candidate.Name, current, candidate.Target, packageCandidateStatus(result, candidate),
		})
	}
	writeTable(os.Stdout, []string{"MANAGER", "PACKAGE", "CURRENT", "LATEST", "STATUS"}, rows)
}

func writeVulnerabilityTable(result scanResult) {
	if len(result.VulnerabilityFindings) == 0 {
		return
	}
	fmt.Println("Vulnerabilities:")
	rows := make([][]string, 0, len(result.VulnerabilityFindings))
	for _, finding := range result.VulnerabilityFindings {
		pkg := finding.Package
		if pkg == "" {
			pkg = "unknown"
		}
		severity := finding.Severity
		if severity == "" {
			severity = "unknown"
		}
		rows = append(rows, []string{finding.ID, pkg, severity})
	}
	writeTable(os.Stdout, []string{"CVE", "PACKAGE", "SEVERITY"}, rows)
}

func writeScanDetails(result scanResult) {
	details := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(details, "  status:\t%s\n", result.Status)
	for _, stage := range result.Stages {
		_, _ = fmt.Fprintf(details, "  stage %s:\t%s\n", stage.Name, stage.Status)
	}
	if len(result.InputCategories) > 0 {
		_, _ = fmt.Fprintf(details, "  inputs:\t%s\n", strings.Join(result.InputCategories, ", "))
	}
	for _, step := range result.Verification {
		_, _ = fmt.Fprintf(details, "  verification:\t%s\n", step)
	}
	if result.PackageUpdates != nil {
		_, _ = fmt.Fprintf(details, "  package updates:\t%s (%s)\n", result.PackageUpdates.Status, result.PackageUpdates.Reason)
	}
	for _, capability := range result.Capabilities {
		if capability.Reason == "" {
			_, _ = fmt.Fprintf(details, "  capability %s:\t%s\n", capability.Name, capability.Status)
		} else {
			_, _ = fmt.Fprintf(details, "  capability %s:\t%s (%s)\n", capability.Name, capability.Status, capability.Reason)
		}
	}
	for _, imageScan := range result.ImageScans {
		if imageScan.Status == "skipped" {
			_, _ = fmt.Fprintf(details, "  image scan %s:\ttier 4, skipped (%s)\n", imageScan.Reference, imageScan.Reason)
			continue
		}
		_, _ = fmt.Fprintf(details, "  image scan %s:\ttier %d, %s (%s)\n", imageScan.Reference, imageScan.Tier, imageScan.ResolvedDigest, imageScan.Platform)
	}
	_ = details.Flush()
}

func packageCandidateStatus(result scanResult, candidate updatesnapshot.Candidate) string {
	if result.Status == config.VerificationScanOnly ||
		(result.PackageUpdates != nil && result.PackageUpdates.Status == config.VerificationScanOnly) {
		return "read-only"
	}
	if !candidate.ReleaseAgeVerified {
		return "age unverified"
	}
	return "available"
}

func conciseScanSummary(result scanResult) string {
	if result.Status == "failed" {
		return "scan failed."
	}
	var parts []string
	if result.Status == "partial" {
		parts = append(parts, "partial scan")
	}
	packagesRequested := scanStageRequested(result, stageCandidate) || len(result.Candidates) > 0 || result.PackageUpdates != nil
	if packagesRequested {
		switch {
		case len(result.Candidates) == 0 && result.Status != "partial":
			parts = append(parts, "no package updates found")
		case len(result.Candidates) > 0 && result.Status == config.VerificationScanOnly:
			parts = append(parts, fmt.Sprintf("%s found (read-only)", countPhrase(len(result.Candidates), "package update", "package updates")))
		case len(result.Candidates) > 0:
			parts = append(parts, fmt.Sprintf("%s available", countPhrase(len(result.Candidates), "package update", "package updates")))
		}
	}
	if scanStageRequested(result, stageVulnerability) || len(result.Vulnerabilities) > 0 {
		if len(result.Vulnerabilities) == 0 && result.Status != "partial" {
			parts = append(parts, "no vulnerabilities found")
		} else if len(result.Vulnerabilities) > 0 {
			parts = append(parts, fmt.Sprintf("%s found", countPhrase(len(result.Vulnerabilities), "vulnerability", "vulnerabilities")))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "scan complete")
	}
	return strings.Join(parts, "; ") + "."
}

func scanStageRequested(result scanResult, name string) bool {
	for _, stage := range result.Stages {
		if stage.Name == name {
			return stage.Status != string(stageNotRequested)
		}
	}
	return false
}

func countPhrase(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
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
