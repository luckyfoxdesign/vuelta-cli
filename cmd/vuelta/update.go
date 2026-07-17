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

	"github.com/luckyfoxdesign/vuelta/internal/autofix"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/localupdate"
	"github.com/luckyfoxdesign/vuelta/internal/logging"
	"github.com/luckyfoxdesign/vuelta/internal/notify"
	"github.com/luckyfoxdesign/vuelta/internal/pipeline"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const exitInterrupted = 130

type updateOptions struct {
	dryRun                    bool
	yes                       bool
	jsonOutput                bool
	execution                 string
	allowScripts              bool
	allowUnverifiedReleaseAge bool
	nonInteractive            bool
	configFile                string
}

type updatePlan struct {
	SnapshotID    string                     `json:"snapshot_id"`
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

func executeUpdate(args []string) error {
	options, id, err := parseUpdateOptions(args)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput || updateJSONRequested(args), "invalid_invocation", err, "Run vuelta help update for usage")
	}
	configFile := options.configFile
	if configFile == "" {
		configFile, err = defaultConfigPath()
		if err != nil {
			return updateTopLevelFailure(options.jsonOutput, "config_unreadable", fail(exitConfig, "%v", err), "Select a valid config with --config")
		}
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "config_unreadable", fail(exitConfig, "%v", err), "Select a valid config with --config")
	}
	warnings := configWarnings(cfg)
	if err := cfg.Validate(); err != nil {
		return updateTopLevelFailure(options.jsonOutput, "config_invalid", fail(exitConfig, "%v", err), "Run vuelta config validate for details")
	}
	stateDir, err := cfg.SnapshotStateDir()
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "config_invalid", fail(exitConfig, "%v", err), "Configure an absolute private snapshot directory")
	}
	snapshot, err := (updatesnapshot.Store{Dir: stateDir}).Load(id)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Run vuelta scan again")
	}
	if err := updatesnapshot.ValidateCandidates(snapshot, options.allowUnverifiedReleaseAge); err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Review the candidate gate and run scan again if needed")
	}

	var workspace *config.Workspace
	var adhocProject localupdate.Project
	switch snapshot.Origin {
	case updatesnapshot.OriginWorkspace:
		if options.execution == "local" {
			return updateTopLevelFailure(options.jsonOutput, "invalid_execution", fail(exitConfig, "registered projects are container-only; --execution local is allowed only for adhoc snapshots"), "Use --execution container")
		}
		selected, selectErr := workspaceForSnapshot(*cfg, snapshot)
		if selectErr != nil {
			return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", selectErr), "Run vuelta scan again")
		}
		if validateErr := updatesnapshot.ValidateForWorkspace(context.Background(), snapshot, *cfg, selected, time.Now()); validateErr != nil {
			return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", validateErr), "Run vuelta scan again")
		}
		workspace = &selected
	case updatesnapshot.OriginAdhoc:
		adhocProject, err = localupdate.Detect(snapshot.AdhocPath)
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
	var result updateResult
	if workspace != nil {
		result, err = executeWorkspaceUpdate(ctx, snapshot, *cfg, *workspace, plan, options)
	} else if options.execution == "local" {
		result, err = executeLocalAdhocUpdate(ctx, snapshot, adhocProject, plan, options)
	} else {
		result, err = executeContainerAdhocUpdate(ctx, snapshot, *cfg, adhocProject, plan, options)
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

func workspaceForSnapshot(cfg config.Config, snapshot updatesnapshot.Snapshot) (config.Workspace, error) {
	for _, workspace := range cfg.Workspaces {
		canonical, err := filepath.EvalSymlinks(workspace.Path)
		if err == nil && canonical == snapshot.Workspace.CanonicalPath {
			return workspace, nil
		}
	}
	return config.Workspace{}, errors.New("snapshot workspace is not configured")
}

func parseUpdateOptions(args []string) (updateOptions, string, error) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var options updateOptions
	fs.BoolVar(&options.dryRun, "dry-run", false, "run without durable changes")
	fs.BoolVar(&options.yes, "yes", false, "confirm the plan")
	fs.BoolVar(&options.jsonOutput, "json", false, "write JSON")
	fs.StringVar(&options.execution, "execution", "container", "container or local")
	fs.BoolVar(&options.allowScripts, "allow-scripts", false, "allow lifecycle scripts")
	fs.BoolVar(&options.allowUnverifiedReleaseAge, "allow-unverified-release-age", false, "allow unverified release age")
	fs.BoolVar(&options.nonInteractive, "non-interactive", false, "disable prompts")
	fs.StringVar(&options.configFile, "internal-config", "", "internal config path")
	if err := fs.Parse(args); err != nil {
		return options, "", fail(exitConfig, "%v", err)
	}
	if options.execution != "container" && options.execution != "local" {
		return options, "", fail(exitConfig, "--execution must be container or local")
	}
	if len(fs.Args()) != 1 {
		return options, "", fail(exitConfig, "update accepts exactly one SNAPSHOT_ID")
	}
	return options, fs.Args()[0], nil
}

func updateJSONRequested(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || strings.HasPrefix(argument, "--json=") {
			return true
		}
	}
	return false
}

func buildUpdatePlan(snapshot updatesnapshot.Snapshot, workspace *config.Workspace, project localupdate.Project, cfg config.Config, options updateOptions) updatePlan {
	target := snapshot.AdhocPath
	files := []string{project.Manifest, project.Lock}
	tests := []string{"disabled: adhoc snapshots have no trusted TestProfile"}
	checks := []string{"snapshot identity and input hashes", "policy identity", "candidate admissibility", "private-copy changed-file allowlist"}
	commit, push := false, "disabled"
	if workspace != nil {
		target = config.WorkspaceName(*workspace)
		files = intendedWorkspaceFiles(snapshot, *workspace)
		tests = []string{fmt.Sprintf("docker compose: %s/%s", workspace.Test.ComposeFile, workspace.Test.Service)}
		checks = []string{"snapshot identity and input hashes", "policy identity", "candidate admissibility", "security baseline and post-check", "configured tests"}
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
		SnapshotID: snapshot.ID, Target: target, Origin: snapshot.Origin, Files: nonNilSorted(files),
		Candidates: candidates,
		Checks:     checks,
		Tests:      tests, Commit: commit, Push: push, Execution: options.execution, DryRun: options.dryRun,
		SecurityGates: map[string]string{
			"lifecycle_scripts":   scripts,
			"project_config":      fmt.Sprintf("scan decision: %t", snapshot.Gates.AllowProjectConfig),
			"minimum_release_age": snapshot.Gates.MinReleaseAge,
			"release_age":         releaseAge,
			"execution":           options.execution,
			"durable_writes":      writeGate,
		},
	}
}

func intendedWorkspaceFiles(snapshot updatesnapshot.Snapshot, workspace config.Workspace) []string {
	filesByManager := map[string][]string{
		"npm": {"package.json", "package-lock.json"}, "pnpm": {"package.json", "pnpm-lock.yaml"},
		"bun": {"package.json", "bun.lock"}, "poetry": {"pyproject.toml", "poetry.lock"},
		"uv": {"pyproject.toml", "uv.lock"}, "pip-tools": {"requirements.in", "requirements.txt"},
	}
	files := append([]string(nil), filesByManager[workspace.PackageManager]...)
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
	writer.printf("  Snapshot: %s\n  Execution: %s\n  Files: %s\n", plan.SnapshotID, plan.Execution, strings.Join(plan.Files, ", "))
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
	logger, err := logging.New(false)
	if err != nil {
		return updateResult{}, fail(exitEnv, "%v", err)
	}
	recheck, err := updater.ResolveCandidateScannerWithOptions(workspace, cfg, updater.CandidateScannerOptions{
		AllowProjectConfig: snapshot.Gates.AllowProjectConfig, RequireTracked: true,
	})
	if err != nil {
		return updateResult{}, fail(exitEnv, "%v", err)
	}
	deps := pipeline.Deps{
		Sandbox: pipeline.BasicSandbox{}, Security: pipeline.DefaultSecurityGate{Scanner: vulnscan.Scanner{}, GitHub: githubalerts.Client{}},
		Autofix: autofix.Runner{}, Notifier: notify.New(cfg.Notify), Logger: logger,
	}
	deps.ResolveUpdater = func(config.Workspace, config.Config) (updater.Updater, error) {
		return updater.PlannedUpdater{
			Candidates: snapshot.Candidates, Workspace: workspace, Config: cfg, AllowScripts: options.allowScripts, Recheck: recheck,
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
		if pipelineResult.Reason == "tests failed" || strings.HasPrefix(pipelineResult.Reason, "test run") {
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

func executeLocalAdhocUpdate(ctx context.Context, snapshot updatesnapshot.Snapshot, project localupdate.Project, plan updatePlan, options updateOptions) (updateResult, error) {
	identity, err := currentAdhocInputIdentity(ctx, project, config.Config{}, snapshot)
	if err != nil {
		return updateResult{}, fail(exitSnapshot, "%v", err)
	}
	if err := updatesnapshot.ValidateForAdhoc(snapshot, project.Root, identity, time.Now()); err != nil {
		return updateResult{}, fail(exitSnapshot, "%v", err)
	}
	policy := config.LocalPackagePolicy{}
	if snapshot.Policy.Path != updatesnapshot.PolicyNone {
		loaded, err := config.LoadLocalPackagePolicy(snapshot.Policy.Path)
		if err != nil {
			return updateResult{}, fail(exitSnapshot, "%v", err)
		}
		policy = loaded
	}
	if len(policy.AllowedPackages) == 0 {
		for _, candidate := range snapshot.Candidates {
			policy.AllowedPackages = append(policy.AllowedPackages, candidate.Name)
		}
	}
	if duration, err := time.ParseDuration(snapshot.Gates.MinReleaseAge); err == nil {
		policy.MinReleaseAgeDays = int((duration + 24*time.Hour - 1) / (24 * time.Hour))
	}
	selected := make([]localupdate.Candidate, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if candidate.Kind != project.Manager {
			return updateResult{}, fail(exitSnapshot, "snapshot candidate %s is not applicable to %s", candidate.Name, project.Manager)
		}
		selected = append(selected, localupdate.Candidate{Name: candidate.Name, Current: candidate.Current, Target: candidate.Target})
	}
	localResult, err := localupdate.NewService().Update(ctx, project.Root, policy, selected, localupdate.UpdateOptions{
		Apply: !options.dryRun, DryRun: options.dryRun, AllowProjectConfig: snapshot.Gates.AllowProjectConfig, AllowScripts: options.allowScripts,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not available on the system PATH") {
			return updateResult{}, fail(exitEnv, "%v", err)
		}
		return updateResult{}, fail(exitFailure, "%v", err)
	}
	status := "updated"
	if options.dryRun {
		status = "dry_run"
	}
	return updateResult{SnapshotID: snapshot.ID, Status: status, Plan: plan, ChangedFiles: nonNilSorted(localResult.ChangedFiles), Tests: "disabled", Commit: "not_created", Push: "not_run"}, nil
}

func executeContainerAdhocUpdate(ctx context.Context, snapshot updatesnapshot.Snapshot, cfg config.Config, project localupdate.Project, plan updatePlan, options updateOptions) (updateResult, error) {
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
	changed, err := localupdate.InPrivateCopy(project.Root, snapshot.Gates.AllowProjectConfig, !options.dryRun, func(privateProject localupdate.Project) error {
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

func currentAdhocInputIdentity(ctx context.Context, project localupdate.Project, cfg config.Config, snapshot updatesnapshot.Snapshot) (updatesnapshot.InputIdentity, error) {
	stages, err := scaninput.ParseStages(snapshot.Input.Stages)
	if err != nil {
		return updatesnapshot.InputIdentity{}, err
	}
	return adhocInputIdentity(ctx, workspaceForAdhoc(project), scanner.IdentityOptions{
		Stages: stages, AllowProjectConfig: snapshot.Gates.AllowProjectConfig, PolicyFile: cfg.VulnScan.PolicyFile,
	})
}
