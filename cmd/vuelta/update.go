package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/adhoc"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/logging"
	"github.com/luckyfoxdesign/vuelta/internal/pipeline"
	"github.com/luckyfoxdesign/vuelta/internal/projectstate"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updatepolicy"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const exitInterrupted = 130

type updateOptions struct {
	dryRun                    bool
	yes                       bool
	jsonOutput                bool
	allowScripts              bool
	allowUnverifiedReleaseAge bool
	nonInteractive            bool
	configFile                string
	directory                 string
	snapshotID                string
	routineOnly               bool
	includeMajor              bool
}

type updatePlan struct {
	SnapshotID    string                     `json:"snapshot_id"`
	CreatedAt     time.Time                  `json:"created_at"`
	ExpiresAt     time.Time                  `json:"expires_at"`
	Target        string                     `json:"target"`
	Origin        string                     `json:"origin"`
	Files         []string                   `json:"files"`
	Candidates    []updatesnapshot.Candidate `json:"candidates"`
	Checks        []string                   `json:"checks"`
	Tests         []string                   `json:"tests"`
	Commit        bool                       `json:"commit"`
	Push          string                     `json:"push"`
	Execution     string                     `json:"execution"`
	DryRun        bool                       `json:"dry_run"`
	SecurityGates map[string]string          `json:"security_gates"`
}

type updateResult struct {
	SnapshotID   string            `json:"snapshot_id"`
	Status       string            `json:"status"`
	Plan         updatePlan        `json:"plan"`
	ChangedFiles []string          `json:"changed_files"`
	Tests        string            `json:"tests"`
	Commit       string            `json:"commit"`
	Push         string            `json:"push"`
	Error        *jsonCommandError `json:"error,omitempty"`
}

type updateSummary struct {
	Status       string `json:"status"`
	ChangedFiles int    `json:"changed_files"`
}

func executeLocalUpdate(args []string) error {
	options, id, err := parseUpdateOptions(args)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput || updateJSONRequested(args), "invalid_invocation", err, "Run vuelta help update for usage")
	}
	selectedPath := options.directory
	if selectedPath == "" {
		selectedPath, err = currentDirectory()
		if err != nil {
			return updateTopLevelFailure(options.jsonOutput, "target_invalid", fail(exitConfig, "resolve current directory: %v", err), "Use --directory with the exact project root")
		}
	}
	target, err := projectstate.Resolve(selectedPath)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "target_invalid", fail(exitConfig, "%v", err), "Use --directory with the exact project root")
	}
	configFile := options.configFile
	if configFile == "" {
		configFile, err = defaultConfigPath()
		if err != nil {
			return updateTopLevelFailure(options.jsonOutput, "config_unreadable", fail(exitConfig, "%v", err), "Fix the operating-system user config directory")
		}
	}
	cfg, err := loadUpdateConfiguration(target.Root, configFile)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "config_unreadable", fail(exitConfig, "%v", err), "Review the selected .vuelta.yaml and machine config; migrate a legacy machine schema explicitly")
	}
	warnings := configWarnings(cfg)
	if err := cfg.Validate(); err != nil {
		return updateTopLevelFailure(options.jsonOutput, "config_invalid", fail(exitConfig, "%v", err), "Run vuelta config validate for details")
	}
	store, err := updatesnapshot.ProjectStore(target.Root)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "target_invalid", fail(exitConfig, "%v", err), "Use the exact canonical project root")
	}
	var snapshot updatesnapshot.Snapshot
	if id == "" {
		snapshot, err = store.LoadLatest()
	} else {
		snapshot, err = store.Load(id)
	}
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Run a new targeted vuelta scan in this project")
	}
	id = snapshot.ID
	if options.routineOnly {
		snapshot.Candidates = routineSnapshotCandidates(snapshot.Candidates, options.includeMajor, time.Now().UTC())
	}
	if err := updatesnapshot.ValidateCandidates(snapshot, options.allowUnverifiedReleaseAge); err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Review the candidate gate and run scan again if needed")
	}

	var workspace *config.Workspace
	var adhocProject adhoc.Project
	switch snapshot.Origin {
	case updatesnapshot.OriginWorkspace:
		if len(cfg.Workspaces) != 1 || cfg.Workspaces[0].Path != target.Root {
			return updateTopLevelFailure(options.jsonOutput, "project_config_unavailable", fail(exitConfig, "selected target has no exact .vuelta.yaml project policy"), "Run vuelta scan in the selected project and review the versioned onboarding files")
		}
		selected := cfg.Workspaces[0]
		if selected.Verification.State != config.VerificationReady {
			return updateTopLevelFailure(options.jsonOutput, "verification_required", fail(exitConfig, "project %q is scan-only; update and update --dry-run are disabled", config.WorkspaceName(selected)), "Configure a ready versioned verification profile and run vuelta scan again")
		}
		if validationErr := testrunner.ValidateProfile(selected.Path, selected.Verification); validationErr != nil {
			return updateTopLevelFailure(options.jsonOutput, "verification_invalid", fail(exitConfig, "%v", validationErr), "Fix the verification profile and run vuelta scan again")
		}
		if validateErr := updatesnapshot.ValidateForWorkspace(context.Background(), snapshot, *cfg, selected, time.Now()); validateErr != nil {
			return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", validateErr), "Run vuelta scan again")
		}
		workspace = &selected
	case updatesnapshot.OriginAdhoc:
		adhocProject, err = adhoc.Detect(target.Root)
		if err != nil {
			return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Restore the scanned directory inputs and run vuelta scan again")
		}
		identity, identityErr := currentAdhocInputIdentity(context.Background(), adhocProject, *cfg, snapshot)
		if identityErr != nil {
			return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", identityErr), "Restore the scanned directory inputs and run vuelta scan again")
		}
		if validateErr := updatesnapshot.ValidateForAdhoc(snapshot, adhocProject.Root, identity, time.Now()); validateErr != nil {
			return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", validateErr), "Run vuelta scan again")
		}
	default:
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "invalid snapshot origin"), "Run vuelta scan again")
	}
	if dockerErr := configureDeveloperDocker(*cfg); dockerErr != nil {
		return updateTopLevelFailure(options.jsonOutput, "environment_unavailable", fail(exitEnv, "%v", dockerErr), "Configure docker.developer for the approved local daemon")
	}
	plan := buildUpdatePlan(snapshot, workspace, adhocProject, *cfg, options)
	planWriter := os.Stdout
	if options.jsonOutput {
		planWriter = os.Stderr
	}
	if err := writeHumanUpdatePlan(planWriter, plan); err != nil {
		return updateResultFailure(options.jsonOutput, plan, warnings, "output_failed", err, "Check the command output stream")
	}
	if !options.dryRun && !options.yes {
		if options.nonInteractive || !configinit.IsTerminal(os.Stdin) {
			return updateResultFailure(options.jsonOutput, plan, warnings, "confirmation_required", fail(exitConfig, "update requires confirmation; rerun with --yes"), "--no-input and --json do not authorize mutation")
		}
		confirmed, confirmErr := promptConfirmation("Apply this update?")
		if confirmErr != nil {
			return updateResultFailure(options.jsonOutput, plan, warnings, "confirmation_failed", fail(exitConfig, "%v", confirmErr), "Rerun with --yes after reviewing the plan")
		}
		if !confirmed {
			result := updateResult{SnapshotID: id, Status: "cancelled", Plan: plan, ChangedFiles: []string{}, Tests: "not_run", Commit: "not_created", Push: "not_run"}
			return writeUpdateOutcome(options.jsonOutput, warnings, result, nil)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	egressSession := egress.NewSession(cfg.Update.Egress, dockerexec.Default())
	ctx = egress.WithSession(ctx, egressSession)
	var result updateResult
	if workspace != nil {
		result, err = executeWorkspaceUpdate(ctx, snapshot, *cfg, *workspace, plan, options)
	} else {
		result, err = executeContainerAdhocUpdate(ctx, snapshot, *cfg, adhocProject, plan, options)
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cleanupErr := egressSession.Close(cleanupCtx)
	cancel()
	if cleanupErr != nil && err == nil {
		err = fail(exitFailure, "managed egress cleanup failed: %v", cleanupErr)
	}
	if ctx.Err() != nil {
		if result.SnapshotID == "" {
			result = updateResult{SnapshotID: id, Plan: plan, ChangedFiles: []string{}, Tests: "not_completed", Commit: "not_created", Push: "not_run"}
		}
		result.Status = "cancelled"
		result.Error = &jsonCommandError{Code: "interrupted", Message: "update interrupted"}
		return writeUpdateOutcome(options.jsonOutput, warnings, result, fail(exitInterrupted, "update interrupted"))
	}
	if err != nil {
		if result.Status == "" {
			result = updateResult{SnapshotID: id, Status: "failed", Plan: plan, ChangedFiles: []string{}, Tests: "not_completed", Commit: "not_created", Push: "not_run"}
		}
		code := "execution_failed"
		var command commandError
		if errors.As(err, &command) && command.code == exitEnv {
			code = "environment_unavailable"
		} else if result.Tests == "failed" {
			code = "test_failed"
		} else if result.Commit == "created" && result.Push == "failed" {
			code = "partial_post_action"
		}
		result.Error = &jsonCommandError{Code: code, Message: err.Error()}
		return writeUpdateOutcome(options.jsonOutput, warnings, result, err)
	}
	return writeUpdateOutcome(options.jsonOutput, warnings, result, nil)
}

func parseUpdateOptions(args []string) (updateOptions, string, error) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var options updateOptions
	fs.BoolVar(&options.dryRun, "dry-run", false, "run without durable changes")
	fs.BoolVar(&options.yes, "yes", false, "confirm the plan")
	fs.BoolVar(&options.jsonOutput, "json", false, "write JSON")
	fs.BoolVar(&options.allowScripts, "allow-scripts", false, "allow lifecycle scripts")
	fs.BoolVar(&options.allowUnverifiedReleaseAge, "allow-unverified-release-age", false, "allow unverified release age")
	fs.BoolVar(&options.nonInteractive, "non-interactive", false, "disable prompts")
	fs.StringVar(&options.configFile, "internal-config", "", "internal config path")
	fs.StringVar(&options.directory, "directory", "", "exact target project directory")
	fs.StringVar(&options.directory, "d", "", "exact target project directory")
	fs.StringVar(&options.snapshotID, "snapshot", "", "select one exact project-local snapshot")
	fs.BoolVar(&options.routineOnly, "routine-only", false, "apply only machine-policy routine candidates")
	fs.BoolVar(&options.includeMajor, "include-major", false, "include eligible stable majors with routine-only")
	if err := fs.Parse(args); err != nil {
		return options, "", fail(exitConfig, "%v", err)
	}
	if optionOccurrences(args, "-d", "--directory") > 1 {
		return options, "", fail(exitConfig, "--directory may be specified only once")
	}
	if optionOccurrences(args, "-d", "--directory") == 1 && options.directory == "" {
		return options, "", fail(exitConfig, "--directory must not be empty")
	}
	if optionOccurrences(args, "--snapshot") > 1 {
		return options, "", fail(exitConfig, "--snapshot may be specified only once")
	}
	if optionOccurrences(args, "--snapshot") == 1 && options.snapshotID == "" {
		return options, "", fail(exitConfig, "--snapshot must not be empty")
	}
	if len(fs.Args()) != 0 {
		return options, "", fail(exitConfig, "positional snapshot IDs are retired; select the target with --directory and use --snapshot ID only for a fresh project-local plan")
	}
	return options, options.snapshotID, nil
}

func routineSnapshotCandidates(candidates []updatesnapshot.Candidate, includeMajor bool, now time.Time) []updatesnapshot.Candidate {
	selected := make([]updatesnapshot.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.PolicyDisposition == updatepolicy.DispositionRoutine && candidate.Direct && candidate.Stable {
			selected = append(selected, candidate)
			continue
		}
		if includeMajor && candidate.Direct && candidate.Stable &&
			candidate.VersionClass == updatepolicy.ClassMajor && !candidate.EligibleAt.After(now) {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func loadUpdateConfiguration(targetRoot, machinePath string) (*config.Config, error) {
	projectPath := filepath.Join(targetRoot, projectConfigName)
	project, projectErr := config.LoadProject(projectPath)
	if errors.Is(projectErr, os.ErrNotExist) {
		machine, _, err := loadMachineAuthorityConfig(machinePath)
		if err != nil {
			return nil, err
		}
		machine.Workspaces = nil
		return machine, nil
	}
	if projectErr != nil {
		return nil, projectErr
	}
	cfg, _, err := mergeProjectWithMachinePath(project, projectPath, "reused", machinePath)
	return cfg, err
}

func updateJSONRequested(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || strings.HasPrefix(argument, "--json=") {
			return true
		}
	}
	return false
}

func buildUpdatePlan(snapshot updatesnapshot.Snapshot, workspace *config.Workspace, project adhoc.Project, cfg config.Config, options updateOptions) updatePlan {
	target := snapshot.AdhocPath
	files := []string{project.Manifest, project.Lock}
	tests := []string{"disabled: adhoc snapshots have no trusted verification profile"}
	checks := []string{"snapshot identity and input hashes", "policy identity", "candidate admissibility", "private-copy changed-file allowlist"}
	commit, push := false, "disabled"
	if workspace != nil {
		target = workspace.Path
		files = intendedWorkspaceFiles(snapshot, *workspace)
		tests = config.VerificationPlan(*workspace)
		checks = []string{"snapshot identity and input hashes", "policy identity", "verification profile identity", "candidate admissibility", "security baseline and post-check", "configured verification"}
		commit = !options.dryRun
		push = cfg.Git.PushMode
		if options.dryRun {
			push = "disabled by dry-run"
		}
	}
	scripts := "blocked"
	if options.allowScripts {
		scripts = "allowed by --allow-scripts"
	}
	releaseAge := "verified"
	if options.allowUnverifiedReleaseAge {
		releaseAge = "unverified candidates allowed by --allow-unverified-release-age"
	}
	writeGate := "confirmation required"
	if options.dryRun {
		writeGate = "durable writes disabled"
	} else if options.yes {
		writeGate = "confirmed by --yes"
	}
	candidates := append([]updatesnapshot.Candidate(nil), snapshot.Candidates...)
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i].Kind + "\x00" + candidates[i].Name + "\x00" + candidates[i].File + "\x00" + candidates[i].Target
		right := candidates[j].Kind + "\x00" + candidates[j].Name + "\x00" + candidates[j].File + "\x00" + candidates[j].Target
		return left < right
	})
	return updatePlan{
		SnapshotID: snapshot.ID, CreatedAt: snapshot.CreatedAt, ExpiresAt: snapshot.ExpiresAt,
		Target: target, Origin: snapshot.Origin, Files: nonNilSorted(files),
		Candidates: candidates,
		Checks:     checks,
		Tests:      tests, Commit: commit, Push: push, Execution: "container", DryRun: options.dryRun,
		SecurityGates: map[string]string{
			"lifecycle_scripts":   scripts,
			"project_config":      fmt.Sprintf("scan decision: %t", snapshot.Gates.AllowProjectConfig),
			"minimum_release_age": snapshot.Gates.MinReleaseAge,
			"verification_hash":   snapshot.VerificationHash,
			"toolchain_profile":   snapshot.Toolchain.ProfileID,
			"toolchain_hash":      snapshot.Toolchain.Hash,
			"toolchain_platform":  snapshot.Toolchain.Platform,
			"release_age":         releaseAge,
			"execution":           "container",
			"durable_writes":      writeGate,
		},
	}
}

func intendedWorkspaceFiles(snapshot updatesnapshot.Snapshot, workspace config.Workspace) []string {
	var files []string
	registry, err := catalog.New()
	if err == nil && workspace.PackageManager != "" {
		if adapter, lookupErr := registry.Lookup(workspace.Stack, workspace.PackageManager); lookupErr == nil {
			if policy, ok := adapter.(ecosystem.ChangePolicy); ok {
				files = policy.AllowedChangedPaths()
			}
		}
	}
	for _, candidate := range snapshot.Candidates {
		if candidate.File != "" {
			files = append(files, candidate.File)
		}
	}
	return files
}

func nonNilSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func writeHumanUpdatePlan(destination *os.File, plan updatePlan) error {
	writer := newTextWriter(destination)
	writer.printf("Update plan for %s (%s)\n", plan.Target, plan.Origin)
	writer.printf("  Snapshot: %s\n  Created: %s\n  Expires: %s\n  Execution: %s\n  Files: %s\n",
		plan.SnapshotID, plan.CreatedAt.UTC().Format(time.RFC3339), plan.ExpiresAt.UTC().Format(time.RFC3339), plan.Execution, strings.Join(plan.Files, ", "))
	for _, candidate := range plan.Candidates {
		writer.printf("  %s %s: %s -> %s\n", candidate.Kind, candidate.Name, candidate.Current, candidate.Target)
	}
	writer.printf("  Tests: %s\n  Commit: %t\n  Push: %s\n", strings.Join(plan.Tests, "; "), plan.Commit, plan.Push)
	keys := make([]string, 0, len(plan.SecurityGates))
	for key := range plan.SecurityGates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writer.printf("  Gate %s: %s\n", key, plan.SecurityGates[key])
	}
	return writer.result()
}

func executeWorkspaceUpdate(ctx context.Context, snapshot updatesnapshot.Snapshot, cfg config.Config, workspace config.Workspace, plan updatePlan, options updateOptions) (updateResult, error) {
	logOutput := os.Stdout
	if options.jsonOutput {
		logOutput = os.Stderr
	}
	logger, err := logging.NewWithOutput(false, logOutput)
	if err != nil {
		return updateResult{}, fail(exitEnv, "%v", err)
	}
	executionProfile, err := resolveWorkspaceExecutionProfile(workspace, cfg, snapshot.Toolchain)
	if err != nil {
		return updateResult{}, fail(exitEnv, "resolve snapshot toolchain: %v", err)
	}
	if executionProfile != nil && snapshot.Toolchain.Source == toolchain.SourceDefault {
		imageID, inspectErr := toolchain.InspectImageID(ctx, dockerexec.Default(), snapshot.Toolchain.ImageID)
		if inspectErr != nil || imageID != snapshot.Toolchain.ImageID {
			return updateResult{}, fail(exitEnv, "snapshot toolchain image is unavailable; run vuelta scan again")
		}
	}
	recheck, err := updater.ResolveCandidateScannerWithOptions(workspace, cfg, updater.CandidateScannerOptions{
		AllowProjectConfig: snapshot.Gates.AllowProjectConfig, RequireTracked: true, ToolchainProfile: executionProfile,
	})
	if err != nil {
		return updateResult{}, fail(exitEnv, "%v", err)
	}
	deps := pipeline.Deps{
		Sandbox: pipeline.BasicSandbox{}, Security: pipeline.DefaultSecurityGate{Scanner: vulnscan.Scanner{}, GitHub: githubalerts.Client{}},
		Logger: logger,
	}
	executionWorkspace := workspace
	executionConfig := cfg
	if executionProfile != nil {
		executionWorkspace.ToolchainProfile = executionProfile.ID
	}
	if executionProfile != nil && snapshot.Toolchain.Source == toolchain.SourceDefault {
		executionConfig.Update.ToolchainProfiles = append(append([]config.ToolchainProfile(nil), cfg.Update.ToolchainProfiles...), *executionProfile)
	}
	deps.ResolveUpdater = func(config.Workspace, config.Config) (updater.Updater, error) {
		return updater.PlannedUpdater{
			Candidates: snapshot.Candidates, Workspace: executionWorkspace, Config: executionConfig, AllowScripts: options.allowScripts, Recheck: recheck,
			Validate: func(validationContext context.Context) error {
				if err := updatesnapshot.ValidateForWorkspace(validationContext, snapshot, cfg, workspace, time.Now()); err != nil {
					return err
				}
				return updatesnapshot.ValidateCandidates(snapshot, options.allowUnverifiedReleaseAge)
			},
		}, nil
	}
	filtered := cfg
	filtered.Workspaces = []config.Workspace{workspace}
	lock, err := pipeline.DefaultLockPath()
	if err != nil {
		return updateResult{}, fail(exitEnv, "resolve update lock: %v", err)
	}
	summary, err := pipeline.Run(ctx, deps, filtered, lock, options.dryRun)
	if err != nil {
		return updateResult{}, fail(exitFailure, "%v", err)
	}
	result := updateResult{SnapshotID: snapshot.ID, Plan: plan, ChangedFiles: []string{}, Tests: "passed", Commit: "not_created", Push: "not_run"}
	if len(summary.Results) != 1 {
		return result, fail(exitFailure, "workspace update returned no result")
	}
	pipelineResult := summary.Results[0]
	result.Status = pipelineResult.Status
	if pipelineResult.Status == "updated" || pipelineResult.Status == "dry_run" {
		result.ChangedFiles = append([]string(nil), plan.Files...)
	}
	if pipelineResult.Status == "updated" {
		result.Commit = "created"
		result.Push = pipelineResult.Branch
	}
	if pipelineResult.Status == "failed" || pipelineResult.Status == "blocked" {
		if pipelineResult.Reason == "verification failed" || strings.HasPrefix(pipelineResult.Reason, "verification run") {
			result.Tests = "failed"
		}
		switch pipelineResult.Reason {
		case "push":
			result.ChangedFiles = append([]string(nil), plan.Files...)
			result.Commit = "created"
			result.Push = "failed"
		case "resolve commit SHA":
			result.ChangedFiles = append([]string(nil), plan.Files...)
			result.Commit = "created (identity unavailable)"
		case "commit":
			result.ChangedFiles = append([]string(nil), plan.Files...)
			result.Commit = "failed"
		}
		if pipelineResult.Reason == "preflight" || pipelineResult.Reason == "resolve updater" || pipelineResult.Reason == "sandbox prepare" {
			return result, fail(exitEnv, "workspace environment unavailable: %s", pipelineResult.Reason)
		}
		return result, fail(exitFailure, "workspace update failed: %s", pipelineResult.Reason)
	}
	return result, nil
}

func resolveWorkspaceExecutionProfile(workspace config.Workspace, cfg config.Config, identity toolchain.Identity) (*config.ToolchainProfile, error) {
	if workspace.PackageManager == "" {
		return nil, nil
	}
	profile, err := toolchain.ResolveSnapshotProfile(workspace, cfg, identity)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func executeContainerAdhocUpdate(ctx context.Context, snapshot updatesnapshot.Snapshot, cfg config.Config, project adhoc.Project, plan updatePlan, options updateOptions) (updateResult, error) {
	if _, err := dockerexec.Default().Path(); err != nil {
		return updateResult{}, fail(exitEnv, "docker is required for container execution: %v", err)
	}
	if _, _, err := egress.Resolve(ctx, cfg.Update.Egress); err != nil {
		return updateResult{}, fail(exitEnv, "%v", err)
	}
	workspace := workspaceForAdhoc(project)
	recheck, err := updater.ResolveCandidateScannerWithOptions(workspace, cfg, updater.CandidateScannerOptions{
		AllowProjectConfig: snapshot.Gates.AllowProjectConfig, RequireTracked: false,
	})
	if err != nil {
		return updateResult{}, fail(exitEnv, "%v", err)
	}
	changed, err := adhoc.InPrivateCopy(project.Root, snapshot.Gates.AllowProjectConfig, !options.dryRun, func(privateProject adhoc.Project) error {
		planned := updater.PlannedUpdater{
			Candidates: snapshot.Candidates, Workspace: workspace, Config: cfg, AllowScripts: options.allowScripts, Recheck: recheck,
			Validate: func(validationContext context.Context) error {
				identity, identityErr := currentAdhocInputIdentity(validationContext, project, cfg, snapshot)
				if identityErr != nil {
					return identityErr
				}
				return updatesnapshot.ValidateForAdhoc(snapshot, project.Root, identity, time.Now())
			},
		}
		_, updateErr := planned.Update(ctx, privateProject.Root)
		return updateErr
	})
	if err != nil {
		return updateResult{}, fail(exitFailure, "%v", err)
	}
	status := "updated"
	if options.dryRun {
		status = "dry_run"
	}
	return updateResult{SnapshotID: snapshot.ID, Status: status, Plan: plan, ChangedFiles: changed, Tests: "disabled", Commit: "not_created", Push: "not_run"}, nil
}

func updateTopLevelFailure(jsonOutput bool, code string, err error, hint string) error {
	if jsonOutput {
		if writeErr := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "update", Results: []updateResult{}, Summary: updateSummary{Status: "failed"}, Warnings: []string{},
			Errors: []jsonCommandError{{Code: code, Message: err.Error(), Hint: hint}},
		}); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func updateResultFailure(jsonOutput bool, plan updatePlan, warnings []string, code string, err error, hint string) error {
	result := updateResult{
		SnapshotID: plan.SnapshotID, Status: "failed", Plan: plan, ChangedFiles: []string{}, Tests: "not_run", Commit: "not_created", Push: "not_run",
		Error: &jsonCommandError{Code: code, Message: err.Error(), Hint: hint},
	}
	return writeUpdateOutcome(jsonOutput, warnings, result, err)
}

func writeUpdateOutcome(jsonOutput bool, warnings []string, result updateResult, commandErr error) error {
	if jsonOutput {
		if err := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "update", Results: []updateResult{result},
			Summary: updateSummary{Status: result.Status, ChangedFiles: len(result.ChangedFiles)}, Warnings: nonNilStrings(warnings), Errors: []jsonCommandError{},
		}); err != nil {
			return err
		}
	} else {
		for _, warning := range warnings {
			fmt.Fprintln(os.Stderr, "warning:", warning)
		}
		destination := os.Stdout
		if commandErr != nil {
			destination = os.Stderr
		}
		writer := newTextWriter(destination)
		writer.printf("Update %s: %s; files=%s; tests=%s; commit=%s; push=%s\n", result.SnapshotID, result.Status, strings.Join(result.ChangedFiles, ","), result.Tests, result.Commit, result.Push)
		if outputErr := writer.result(); outputErr != nil {
			return errors.Join(commandErr, outputErr)
		}
	}
	return commandErr
}

func currentAdhocInputIdentity(ctx context.Context, project adhoc.Project, cfg config.Config, snapshot updatesnapshot.Snapshot) (updatesnapshot.InputIdentity, error) {
	stages, err := scaninput.ParseStages(snapshot.Input.Stages)
	if err != nil {
		return updatesnapshot.InputIdentity{}, err
	}
	return adhocInputIdentity(ctx, workspaceForAdhoc(project), scanner.IdentityOptions{
		Stages: stages, AllowProjectConfig: snapshot.Gates.AllowProjectConfig, PolicyFile: cfg.VulnScan.PolicyFile,
	})
}
