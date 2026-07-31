package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/deploy"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/history"
)

func executeDeploy(args []string) error {
	return executeDeploySelection(args, false)
}

func executeDeploySync(args []string) error {
	return executeDeploySelection(args, true)
}

func executeDeploySelection(args []string, all bool) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	positionals := fs.Args()
	project := ""
	if !all {
		if len(positionals) == 0 {
			return fail(exitConfig, "deploy requires PROJECT; ordinary unattended work uses 'vuelta deploy sync'")
		}
		project = positionals[0]
		positionals = positionals[1:]
	}
	selectedConfig, err := configPath(positionals)
	if err != nil {
		return err
	}
	cfg, err := loadMachineConfig(selectedConfig, false)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if err := cfg.Validate(); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if !cfg.Deploy.Enabled {
		return fail(exitConfig, "automatic deploy is disabled in machine config")
	}
	store, err := openHistoryStore(context.Background(), cfg, selectedConfig)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	defer func() { _ = store.Close() }()
	client, err := githubActionsClient(cfg)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	runtime, err := deploymentRuntime(cfg, store)
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	var results []deploy.SyncResult
	var syncErrors []error
	for _, workspace := range cfg.Workspaces {
		name := config.WorkspaceName(workspace)
		if project != "" && name != project {
			continue
		}
		result, syncErr := deploy.SyncProject(
			context.Background(), workspace, *cfg, store, client, runtime, time.Now().UTC(),
		)
		if syncErr != nil {
			syncErrors = append(syncErrors, fmt.Errorf("%s: %w", name, syncErr))
			if result.Project == "" {
				result.Project = name
			}
			if result.Status == "" {
				result.Status = "failed"
			}
			result.Blockers = append(result.Blockers, "sync_failed")
			results = append(results, result)
			continue
		}
		results = append(results, result)
	}
	if project != "" && len(results) == 0 {
		return fail(exitConfig, "project %q must match exactly one configured workspace", project)
	}
	command := "deploy"
	if all {
		command = "deploy sync"
	}
	if jsonOutput {
		commandErr := errors.Join(syncErrors...)
		errorsOutput := []jsonCommandError{}
		if commandErr != nil {
			errorsOutput = append(errorsOutput, jsonCommandError{
				Code: "deploy_sync_failed", Message: commandErr.Error(),
			})
		}
		if err := writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: command, Results: results,
			Summary: map[string]any{"projects": len(results)}, Warnings: []string{}, Errors: errorsOutput,
		}); err != nil {
			return err
		}
		return commandErr
	}
	writer := newTextWriter(os.Stdout)
	for _, result := range results {
		writer.printf("%-16s %-12s %s\n", result.Project, result.Status, result.RunURL)
		for _, blocker := range result.Blockers {
			writer.printf("  blocked: %s\n", blocker)
		}
	}
	if err := writer.result(); err != nil {
		return err
	}
	return errors.Join(syncErrors...)
}

func executeDeployPlan(args []string) error {
	fs := flag.NewFlagSet("deploy plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) == 0 {
		return fail(exitConfig, "deploy plan requires PROJECT")
	}
	project := fs.Args()[0]
	selectedConfig, err := configPath(fs.Args()[1:])
	if err != nil {
		return err
	}
	cfg, err := loadMachineConfig(selectedConfig, false)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	workspace, err := exactDeploymentWorkspace(cfg, project)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	contract, err := deploy.Discover(context.Background(), workspace)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	if jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "deploy plan", Results: []deploy.Contract{contract},
			Summary: map[string]any{
				"project": project, "ready": len(contract.Blockers) == 0,
				"repository_writes": false,
			},
			Warnings: []string{}, Errors: []jsonCommandError{},
		})
	}
	writer := newTextWriter(os.Stdout)
	writer.printf("Project: %s\n", contract.Project)
	writer.printf("Repository: %s\n", contract.Repository)
	writer.printf("Commit: %s\n", contract.Commit)
	writer.printf("Compose: %v\n", contract.ComposeFiles)
	writer.printf("Services: %d\n", len(contract.Services))
	writer.printf("Traffic: %s:%d via stable upstream %s\n",
		contract.TrafficService, contract.InternalPort, contract.StableUpstream)
	writer.println("Repository writes: none")
	for _, blocker := range contract.Blockers {
		writer.printf("Blocked: %s\n", blocker)
	}
	return writer.result()
}

func executeDeployStatus(args []string) error {
	fs := flag.NewFlagSet("deploy status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	positionals := fs.Args()
	project := ""
	if len(positionals) > 0 && positionals[0] != "--" {
		project = positionals[0]
		positionals = positionals[1:]
	}
	selectedConfig, err := configPath(positionals)
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
	defer func() { _ = store.Close() }()
	contracts, err := store.DeploymentContracts(context.Background())
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	releases, err := store.DeploymentReleases(context.Background(), project, 100)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	if jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "deploy status", Results: releases,
			Summary:  map[string]any{"contracts": contracts, "releases": len(releases)},
			Warnings: []string{}, Errors: []jsonCommandError{},
		})
	}
	writer := newTextWriter(os.Stdout)
	for _, contract := range contracts {
		if project == "" || contract.ProjectName == project {
			writer.printf("%-16s contract %-8s %s\n", contract.ProjectName, contract.Status, contract.Fingerprint)
		}
	}
	for _, release := range releases {
		writer.printf("%-16s %-12s %s %s\n",
			release.ProjectName, release.State, release.SourceCommit, release.CandidateDigest)
	}
	return writer.result()
}

func executeDeployRollback(args []string) error {
	fs := flag.NewFlagSet("deploy rollback", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := false
	fs.BoolVar(&jsonOutput, "json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) == 0 {
		return fail(exitConfig, "deploy rollback requires PROJECT")
	}
	project := fs.Args()[0]
	selectedConfig, err := configPath(fs.Args()[1:])
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
	defer func() { _ = store.Close() }()
	releases, err := store.DeploymentReleases(context.Background(), project, 1)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	if len(releases) == 0 || releases[0].PreviousDigest == "" {
		return fail(exitConfig, "project %q has no recorded immutable rollback digest", project)
	}
	workspace, err := exactDeploymentWorkspace(cfg, project)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	contract, err := deploy.Discover(context.Background(), workspace)
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	runtime, err := deploymentRuntime(cfg, store)
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	rolledBack, err := runtime.Rollback(context.Background(), contract, releases[0], time.Now().UTC())
	if err != nil {
		return fail(exitFailure, "%v", err)
	}
	if jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "deploy rollback", Results: []any{rolledBack},
			Summary:  map[string]any{"project": project, "status": rolledBack.State},
			Warnings: []string{}, Errors: []jsonCommandError{},
		})
	}
	writer := newTextWriter(os.Stdout)
	writer.printf("%s restored %s\n", project, rolledBack.PreviousDigest)
	return writer.result()
}

func exactDeploymentWorkspace(cfg *config.Config, project string) (config.Workspace, error) {
	var matches []config.Workspace
	for _, workspace := range cfg.Workspaces {
		if config.WorkspaceName(workspace) == project {
			matches = append(matches, workspace)
		}
	}
	if len(matches) != 1 {
		return config.Workspace{}, fmt.Errorf("project %q must match exactly one configured workspace", project)
	}
	return matches[0], nil
}

func deploymentRuntime(cfg *config.Config, store *history.Store) (*deploy.Runtime, error) {
	if cfg == nil || store == nil {
		return nil, errors.New("deployment runtime configuration is missing")
	}
	if err := configureDeveloperDocker(*cfg); err != nil {
		return nil, err
	}
	token, ok := os.LookupEnv(cfg.GithubActions.TokenEnv)
	if !ok || token == "" {
		return nil, errors.New("configured GitHub token is unavailable for GHCR pull")
	}
	driver, err := deploy.NewDockerDriver(deploy.DockerDriverOptions{
		Runner:          dockerexec.Default(),
		StateDir:        filepath.Join(filepath.Dir(store.Path()), "deploy"),
		GatewayImage:    cfg.Deploy.GatewayImage,
		RegistryUser:    cfg.GithubActions.RegistryUser,
		RegistryToken:   token,
		MinFreeMemoryMB: cfg.Deploy.MinFreeMemoryMB,
		MinFreeDiskMB:   cfg.Deploy.MinFreeDiskMB,
	})
	if err != nil {
		return nil, err
	}
	drain := time.Duration(cfg.Deploy.DrainSeconds) * time.Second
	return &deploy.Runtime{Driver: driver, Store: store, DrainTimeout: drain}, nil
}
