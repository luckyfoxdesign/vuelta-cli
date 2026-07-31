package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/githubactions"
	"github.com/luckyfoxdesign/vuelta/internal/history"
	"github.com/luckyfoxdesign/vuelta/internal/updatepolicy"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

type remoteUpdateOptions struct {
	yes            bool
	jsonOutput     bool
	includeMajor   bool
	nonInteractive bool
	configFile     string
}

type remoteUpdatePlan struct {
	Project            string                     `json:"project"`
	Repository         string                     `json:"repository"`
	Workflow           string                     `json:"workflow"`
	BaseCommit         string                     `json:"base_commit"`
	SnapshotID         string                     `json:"snapshot_id"`
	RoutineCandidates  []updatesnapshot.Candidate `json:"routine_candidates"`
	DeferredCandidates []updatesnapshot.Candidate `json:"deferred_candidates"`
	Execution          string                     `json:"execution"`
	ServerMutation     bool                       `json:"server_mutation"`
}

type remoteUpdateResult struct {
	Status  string           `json:"status"`
	Project string           `json:"project"`
	RunID   int64            `json:"github_run_id,omitempty"`
	RunURL  string           `json:"run_url,omitempty"`
	Plan    remoteUpdatePlan `json:"plan"`
	Stale   bool             `json:"stale,omitempty"`
}

func executeUpdate(args []string) error {
	if containsAnyOption(args, "-d", "--directory", "--snapshot", "--dry-run", "--allow-scripts", "--allow-unverified-release-age") {
		return fail(exitConfig, "local mutation flags moved to the explicit compatibility command: vuelta update local")
	}
	options, project, err := parseRemoteUpdateOptions(args)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput || updateJSONRequested(args), "invalid_invocation", err, "Run vuelta help update for usage")
	}
	cfg, configPath, err := loadRemoteMachineConfig(options.configFile)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "config_unreadable", fail(exitConfig, "%v", err), "Select a valid machine config")
	}
	workspace, err := exactUpdateWorkspace(cfg, project)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "project_config_unavailable", fail(exitConfig, "%v", err), "Configure one exact project and its GitHub update workflow")
	}
	snapshotStore, err := updatesnapshot.ProjectStore(workspace.Path)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Run a targeted vuelta scan")
	}
	snapshot, err := snapshotStore.LoadLatest()
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Run a targeted vuelta scan")
	}
	if snapshot.Project != project || snapshot.Workspace.BaseRevision == "" {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "latest snapshot does not match project %q and an exact base commit", project), "Run a targeted vuelta scan")
	}
	if err := updatesnapshot.ValidateForWorkspace(context.Background(), snapshot, *cfg, workspace, time.Now()); err != nil {
		return updateTopLevelFailure(options.jsonOutput, "snapshot_invalid", fail(exitSnapshot, "%v", err), "Run a new targeted vuelta scan from the exact base commit")
	}
	plan, err := buildRemoteUpdatePlan(project, workspace, snapshot, options.includeMajor)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "no_routine_candidates", fail(exitConfig, "%v", err), "Wait for cooldown, review deferred candidates, or run a new scan")
	}
	planWriter := os.Stdout
	if options.jsonOutput {
		planWriter = os.Stderr
	}
	if err := writeRemoteUpdatePlan(planWriter, plan); err != nil {
		return err
	}
	if !options.yes {
		if options.nonInteractive || options.jsonOutput || !configinit.IsTerminal(os.Stdin) {
			return updateTopLevelFailure(options.jsonOutput, "confirmation_required", fail(exitConfig, "update dispatch requires confirmation; rerun with --yes"), "--no-input and --json do not authorize a GitHub workflow")
		}
		confirmed, confirmErr := promptConfirmation("Dispatch this GitHub update?")
		if confirmErr != nil {
			return fail(exitConfig, "%v", confirmErr)
		}
		if !confirmed {
			return writeRemoteUpdateOutcome(options.jsonOutput, nil, remoteUpdateResult{
				Status: "cancelled", Project: project, Plan: plan,
			}, nil)
		}
	}
	stateStore, err := openHistoryStore(context.Background(), cfg, configPath)
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "history_unavailable", fail(exitFailure, "%v", err), "Repair the machine-owned SQLite state before dispatching")
	}
	defer func() { _ = stateStore.Close() }()
	operationID, err := stateStore.RecordOperation(context.Background(), history.Operation{
		ProjectName: project, ProjectRoot: workspace.Path, Kind: "update", Status: "dispatching",
		Event: history.OperationEvent{
			Type: "update_dispatch_started", Summary: project + " update dispatch started",
			IdempotencyKey: "dispatch-started",
		},
	})
	if err != nil {
		return updateTopLevelFailure(options.jsonOutput, "history_write_failed", fail(exitFailure, "%v", err), "No GitHub workflow was dispatched")
	}
	client, err := githubActionsClient(cfg)
	if err != nil {
		_, _ = stateStore.RecordOperation(context.Background(), history.Operation{
			ID: operationID, ProjectName: project, ProjectRoot: workspace.Path,
			Kind: "update", Status: "failed",
			Event: history.OperationEvent{
				Type: "update_dispatch_failed", Summary: project + " update dispatch failed",
				IdempotencyKey: "dispatch-failed", Notify: true,
			},
		})
		return updateTopLevelFailure(options.jsonOutput, "github_unavailable", fail(exitConfig, "%v", err), "Configure the fixed GitHub token environment reference")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	run, dispatchErr := client.Dispatch(ctx, githubactions.DispatchRequest{
		Repository: workspace.Github.Repository, Workflow: workspace.Github.Workflow,
		BaseCommit: snapshot.Workspace.BaseRevision, RequestID: operationID,
		IncludeMajor: options.includeMajor, Ref: workspace.Branch,
	})
	if dispatchErr != nil {
		_, _ = stateStore.RecordOperation(context.Background(), history.Operation{
			ID: operationID, ProjectName: project, ProjectRoot: workspace.Path,
			Kind: "update", Status: "failed",
			Event: history.OperationEvent{
				Type: "update_dispatch_failed", Summary: project + " update dispatch failed",
				IdempotencyKey: "dispatch-failed", Notify: true,
			},
		})
		return updateTopLevelFailure(options.jsonOutput, "github_dispatch_failed", fail(exitFailure, "%v", dispatchErr), "The server checkout was not modified")
	}
	job := history.UpdateJob{
		OperationID: operationID, ProjectName: project, ProjectRoot: workspace.Path,
		Repository: workspace.Github.Repository, Workflow: workspace.Github.Workflow,
		GitHubRunID: run.ID, RunURL: run.URL, RequestedCommit: snapshot.Workspace.BaseRevision,
		Status: run.Status, RequestedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt,
	}
	if err := stateStore.RecordUpdateJob(context.Background(), job); err != nil {
		return writeRemoteUpdateOutcome(options.jsonOutput, nil, remoteUpdateResult{
			Status: "history_write_failed", Project: project, RunID: run.ID, RunURL: run.URL, Plan: plan,
		}, fail(exitFailure, "GitHub run was created but could not be recorded: %v", err))
	}
	_, eventErr := stateStore.RecordOperation(context.Background(), history.Operation{
		ID: operationID, ProjectName: project, ProjectRoot: workspace.Path,
		Kind: "update", Status: run.Status, At: run.UpdatedAt,
		Event: history.OperationEvent{
			Type: "update_requested", Summary: project + " GitHub update requested",
			IdempotencyKey: "github-run-created", Notify: true,
		},
	})
	if eventErr != nil {
		return writeRemoteUpdateOutcome(options.jsonOutput, nil, remoteUpdateResult{
			Status: "queued", Project: project, RunID: run.ID, RunURL: run.URL, Plan: plan,
		}, fail(exitFailure, "GitHub run is recorded but its outbox event failed: %v", eventErr))
	}
	return writeRemoteUpdateOutcome(options.jsonOutput, nil, remoteUpdateResult{
		Status: run.Status, Project: project, RunID: run.ID, RunURL: run.URL, Plan: plan,
	}, nil)
}

func parseRemoteUpdateOptions(args []string) (remoteUpdateOptions, string, error) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var options remoteUpdateOptions
	fs.BoolVar(&options.yes, "yes", false, "confirm the dispatch")
	fs.BoolVar(&options.jsonOutput, "json", false, "write JSON")
	fs.BoolVar(&options.includeMajor, "include-major", false, "include reviewed majors")
	fs.BoolVar(&options.nonInteractive, "non-interactive", false, "disable prompts")
	fs.StringVar(&options.configFile, "internal-config", "", "internal config path")
	if err := fs.Parse(args); err != nil {
		return options, "", fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) != 1 || fs.Args()[0] == "" {
		return options, "", fail(exitConfig, "update requires one configured PROJECT")
	}
	return options, fs.Args()[0], nil
}

func containsAnyOption(args []string, names ...string) bool {
	for _, argument := range args {
		name, _, _ := strings.Cut(argument, "=")
		for _, expected := range names {
			if name == expected {
				return true
			}
		}
	}
	return false
}

func loadRemoteMachineConfig(selected string) (*config.Config, string, error) {
	path := selected
	var err error
	if path == "" {
		path, err = defaultConfigPath()
		if err != nil {
			return nil, "", err
		}
	}
	cfg, err := loadMachineConfig(path, false)
	if err != nil {
		return nil, "", err
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

func exactUpdateWorkspace(cfg *config.Config, name string) (config.Workspace, error) {
	var matches []config.Workspace
	for _, workspace := range cfg.Workspaces {
		if config.WorkspaceName(workspace) == name {
			matches = append(matches, workspace)
		}
	}
	if len(matches) != 1 {
		return config.Workspace{}, fmt.Errorf("project %q must match exactly one configured workspace", name)
	}
	workspace := matches[0]
	canonical, err := canonicalDirectory(workspace.Path)
	if err != nil {
		return config.Workspace{}, err
	}
	workspace.Path = canonical
	project, projectErr := config.LoadProject(filepath.Join(canonical, projectConfigName))
	switch {
	case projectErr == nil:
		versioned, resolveErr := project.ResolvedWorkspace(filepath.Join(canonical, projectConfigName))
		if resolveErr != nil {
			return config.Workspace{}, resolveErr
		}
		if versioned.Path != canonical {
			return config.Workspace{}, fmt.Errorf("project %q versioned policy resolves to a different root", name)
		}
		versioned.ToolchainProfile = workspace.ToolchainProfile
		workspace = versioned
	case !errors.Is(projectErr, os.ErrNotExist):
		return config.Workspace{}, projectErr
	}
	if workspace.Github == nil {
		return config.Workspace{}, fmt.Errorf("project %q has no versioned github workflow configuration", name)
	}
	return workspace, nil
}

func buildRemoteUpdatePlan(project string, workspace config.Workspace, snapshot updatesnapshot.Snapshot, includeMajor bool) (remoteUpdatePlan, error) {
	plan := remoteUpdatePlan{
		Project: project, Repository: workspace.Github.Repository, Workflow: workspace.Github.Workflow,
		BaseCommit: snapshot.Workspace.BaseRevision, SnapshotID: snapshot.ID,
		RoutineCandidates: []updatesnapshot.Candidate{}, DeferredCandidates: []updatesnapshot.Candidate{},
		Execution: "github-hosted", ServerMutation: false,
	}
	for _, candidate := range snapshot.Candidates {
		switch {
		case candidate.PolicyDisposition == updatepolicy.DispositionRoutine && candidate.Direct && candidate.Stable:
			plan.RoutineCandidates = append(plan.RoutineCandidates, candidate)
		case includeMajor && candidate.Direct && candidate.Stable && candidate.VersionClass == updatepolicy.ClassMajor &&
			!candidate.EligibleAt.After(time.Now().UTC()):
			plan.RoutineCandidates = append(plan.RoutineCandidates, candidate)
		default:
			plan.DeferredCandidates = append(plan.DeferredCandidates, candidate)
		}
	}
	if len(plan.RoutineCandidates) == 0 {
		return remoteUpdatePlan{}, errors.New("latest successful scan has no eligible routine candidates")
	}
	return plan, nil
}

func writeRemoteUpdatePlan(destination *os.File, plan remoteUpdatePlan) error {
	writer := newTextWriter(destination)
	writer.printf("Project: %s\n", plan.Project)
	writer.printf("Repository: %s\n", plan.Repository)
	writer.printf("Base commit: %s\n", plan.BaseCommit)
	writer.printf("Routine candidates: %d\n", len(plan.RoutineCandidates))
	for _, candidate := range plan.RoutineCandidates {
		writer.printf("  %s/%s %s -> %s (%s)\n", candidate.Kind, candidate.Name, candidate.Current, candidate.Target, candidate.VersionClass)
	}
	writer.printf("Deferred candidates: %d\n", len(plan.DeferredCandidates))
	writer.println("Execution: GitHub-hosted runner; the server checkout will not be modified.")
	return writer.result()
}

func githubActionsClient(cfg *config.Config) (*githubactions.Client, error) {
	if cfg.GithubActions.TokenEnv == "" {
		return nil, errors.New("github_actions.token_env is required")
	}
	token, ok := os.LookupEnv(cfg.GithubActions.TokenEnv)
	if !ok || token == "" {
		return nil, fmt.Errorf("configured GitHub token variable %s is not set", cfg.GithubActions.TokenEnv)
	}
	return githubactions.New(githubactions.Config{APIURL: cfg.GithubActions.APIURL, Token: token})
}

func openHistoryStore(ctx context.Context, cfg *config.Config, configPath string) (*history.Store, error) {
	path, err := history.ResolvePath(configPath, cfg.State.DatabasePath)
	if err != nil {
		return nil, err
	}
	return history.Open(ctx, path)
}

func writeRemoteUpdateOutcome(jsonOutput bool, warnings []string, result remoteUpdateResult, commandErr error) error {
	if jsonOutput {
		errorsOutput := []jsonCommandError{}
		if commandErr != nil {
			errorsOutput = append(errorsOutput, jsonCommandError{Code: "update_failed", Message: commandErr.Error()})
		}
		if err := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "update", Results: []remoteUpdateResult{result},
			Summary: map[string]any{"status": result.Status}, Warnings: warnings, Errors: errorsOutput,
		}); err != nil {
			return err
		}
		return commandErr
	}
	if result.RunURL != "" {
		writer := newTextWriter(os.Stdout)
		writer.println()
		writer.println("Requested GitHub update job:")
		writer.println(result.RunURL)
		writer.println()
		writer.println("The server did not modify the project checkout.")
		if err := writer.result(); err != nil && commandErr == nil {
			return err
		}
	}
	return commandErr
}

func executeUpdateStatus(args []string) error {
	return executeDurableStatus(args, true)
}

func executeStatus(args []string) error {
	return executeDurableStatus(args, false)
}

func executeDurableStatus(args []string, updateOnly bool) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	positionals := fs.Args()
	project := ""
	configArgs := positionals
	if updateOnly && len(positionals) > 0 && positionals[0] != "--" {
		project = positionals[0]
		configArgs = positionals[1:]
	}
	configPath, err := configPath(configArgs)
	if err != nil {
		return err
	}
	cfg, err := loadMachineConfig(configPath, false)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	store, err := openHistoryStore(context.Background(), cfg, configPath)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	defer func() { _ = store.Close() }()
	warnings := synchronizeKnownUpdateJobs(context.Background(), cfg, store, project)
	jobs, err := store.UpdateJobs(context.Background(), project, 100)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	statuses, err := store.Status(context.Background())
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	command := "status"
	if updateOnly {
		command = "update status"
	}
	if jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: command, Results: jobs,
			Summary:  map[string]any{"projects": statuses, "jobs": len(jobs)},
			Warnings: warnings, Errors: []jsonCommandError{},
		})
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	writer := newTextWriter(os.Stdout)
	if !updateOnly {
		for _, status := range statuses {
			writer.printf("%-16s %d routine, %d deferred · %s\n",
				status.Project, status.Routine, status.Deferred, status.ScanStatus)
		}
	}
	for _, job := range jobs {
		writer.printf("%-16s %-12s %s\n", job.ProjectName, job.Status, job.RunURL)
	}
	return writer.result()
}

func synchronizeKnownUpdateJobs(ctx context.Context, cfg *config.Config, store *history.Store, project string) []string {
	jobs, err := store.PendingUpdateJobs(ctx, project)
	if err != nil {
		return []string{"update job synchronization failed: " + err.Error()}
	}
	if len(jobs) == 0 {
		return nil
	}
	client, err := githubActionsClient(cfg)
	if err != nil {
		return []string{"update job status is stale: " + err.Error()}
	}
	var warnings []string
	for _, job := range jobs {
		run, readErr := client.GetRun(ctx, job.Repository, job.GitHubRunID)
		if readErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s run %d is stale: %v", job.ProjectName, job.GitHubRunID, readErr))
			continue
		}
		if run.HeadSHA != job.RequestedCommit {
			warnings = append(warnings, fmt.Sprintf("%s run %d returned a mismatched base commit and was ignored", job.ProjectName, job.GitHubRunID))
			continue
		}
		status := run.Status
		if run.Status == "completed" {
			if run.Conclusion == "success" {
				status = "succeeded"
			} else {
				status = "failed"
			}
		}
		job.Status, job.Branch, job.UpdatedAt = status, run.HeadBranch, run.UpdatedAt
		event := history.OperationEvent{
			Type: "update_" + status, Summary: job.ProjectName + " GitHub update " + status,
			IdempotencyKey: fmt.Sprintf("github-%s-%s-%s", run.Status, run.Conclusion, run.UpdatedAt.Format(time.RFC3339Nano)),
			Notify:         status == "succeeded" || status == "failed",
		}
		if writeErr := store.UpdateJobState(ctx, job, event); writeErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s run %d status write failed: %v", job.ProjectName, job.GitHubRunID, writeErr))
		}
	}
	return warnings
}

func executeHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) < 1 {
		return fail(exitConfig, "history requires PROJECT")
	}
	project := fs.Args()[0]
	configPath, err := configPath(fs.Args()[1:])
	if err != nil {
		return err
	}
	cfg, err := loadMachineConfig(configPath, false)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	store, err := openHistoryStore(context.Background(), cfg, configPath)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	defer func() { _ = store.Close() }()
	events, err := store.ProjectHistory(context.Background(), project, 100)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	if jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "history", Results: events,
			Summary:  map[string]any{"project": project, "events": len(events)},
			Warnings: []string{}, Errors: []jsonCommandError{},
		})
	}
	writer := newTextWriter(os.Stdout)
	for _, event := range events {
		writer.printf("%s  %s/%s  %s -> %s\n",
			event.ObservedAt.Local().Format(time.RFC3339), event.Ecosystem, event.Name, event.From, event.To)
	}
	return writer.result()
}

func executeCommandConsume(args []string) error {
	fs := flag.NewFlagSet("commands consume", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	selectedConfig, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	cfg, err := loadMachineConfig(selectedConfig, false)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	store, err := openHistoryStore(context.Background(), cfg, selectedConfig)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	command, err := store.ClaimOperatorCommand(context.Background(), time.Now().UTC())
	if closeErr := store.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	if command == nil {
		if jsonOutput {
			return writeJSONEnvelope(jsonCommandEnvelope{
				Format: 1, Command: "commands consume", Results: []any{},
				Summary: map[string]any{"consumed": 0}, Warnings: []string{}, Errors: []jsonCommandError{},
			})
		}
		writer := newTextWriter(os.Stdout)
		writer.println("No pending typed operator command.")
		return writer.result()
	}
	if time.Since(command.CreatedAt) > 15*time.Minute || command.CreatedAt.After(time.Now().UTC().Add(time.Minute)) {
		if completionErr := completeOperatorCommand(cfg, selectedConfig, command.ID, false); completionErr != nil {
			return fail(exitFailure, "reject stale command: %v", completionErr)
		}
		return fail(exitConfig, "typed operator command %s is stale and was rejected", command.ID)
	}
	var dispatchErr error
	switch command.Type {
	case "request_update":
		dispatchArgs := []string{"--yes", "--non-interactive", "--internal-config", selectedConfig}
		if jsonOutput {
			dispatchArgs = append(dispatchArgs, "--json")
		}
		dispatchArgs = append(dispatchArgs, command.Project)
		dispatchErr = executeUpdate(dispatchArgs)
	case "request_deploy":
		dispatchArgs := []string{}
		if jsonOutput {
			dispatchArgs = append(dispatchArgs, "--json")
		}
		dispatchArgs = append(dispatchArgs, command.Project, "--", selectedConfig)
		dispatchErr = executeDeploy(dispatchArgs)
	case "request_rollback":
		dispatchArgs := []string{}
		if jsonOutput {
			dispatchArgs = append(dispatchArgs, "--json")
		}
		dispatchArgs = append(dispatchArgs, command.Project, "--", selectedConfig)
		dispatchErr = executeDeployRollback(dispatchArgs)
	default:
		dispatchErr = fail(exitConfig, "typed operator command %s is not executable by this consumer", command.Type)
	}
	if completionErr := completeOperatorCommand(cfg, selectedConfig, command.ID, dispatchErr == nil); completionErr != nil {
		if dispatchErr != nil {
			return errors.Join(dispatchErr, completionErr)
		}
		return fail(exitFailure, "%v", completionErr)
	}
	return dispatchErr
}

func completeOperatorCommand(cfg *config.Config, configPath, commandID string, succeeded bool) error {
	store, err := openHistoryStore(context.Background(), cfg, configPath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	return store.CompleteCommand(context.Background(), commandID, succeeded, time.Now().UTC())
}
