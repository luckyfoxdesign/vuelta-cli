package deploy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/githubactions"
	"github.com/luckyfoxdesign/vuelta/internal/history"
)

// ReleaseClient is the central GitHub release surface used by timer sync.
type ReleaseClient interface {
	DispatchRelease(context.Context, githubactions.ReleaseDispatchRequest) (githubactions.Run, error)
	GetRun(context.Context, string, int64) (githubactions.Run, error)
	BranchHead(context.Context, string, string) (string, error)
}

// SyncResult is the bounded result of one automatically discovered workspace.
type SyncResult struct {
	Project     string   `json:"project"`
	Status      string   `json:"status"`
	Commit      string   `json:"commit,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	RunURL      string   `json:"run_url,omitempty"`
	Blockers    []string `json:"blockers"`
}

// SyncProject performs discovery and release synchronization. Runtime
// deployment begins only after a successful exact release build and is kept
// behind RuntimeDeployer so tests never need Docker or network access.
func SyncProject(
	ctx context.Context,
	workspace config.Workspace,
	cfg config.Config,
	store *history.Store,
	client ReleaseClient,
	runtime RuntimeDeployer,
	now time.Time,
) (SyncResult, error) {
	if store == nil {
		return SyncResult{}, errors.New("deployment history store is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	contract, err := Discover(ctx, workspace)
	if err != nil {
		return SyncResult{}, err
	}
	if contract.Repository != "" && client != nil {
		head, headErr := client.BranchHead(ctx, contract.Repository, contract.Branch)
		if headErr != nil {
			contract.Blockers = append(contract.Blockers, "github_branch_head_unresolved")
		} else {
			contract.Commit = head
			contract.Blockers = without(contract.Blockers, "git_commit_unresolved")
			contract.Blockers = uniqueSorted(contract.Blockers)
			contract.Fingerprint, err = fingerprint(contract)
			if err != nil {
				return SyncResult{}, err
			}
		}
	}
	status := "ready"
	if len(contract.Blockers) > 0 {
		status = "blocked"
	}
	serviceNames := make([]string, 0, len(contract.Services))
	for _, service := range contract.Services {
		serviceNames = append(serviceNames, service.Name)
	}
	if err := store.RecordDeploymentContract(ctx, history.DeploymentContract{
		ProjectName: contract.Project, ProjectRoot: contract.Root,
		Fingerprint: contract.Fingerprint, Repository: contract.Repository,
		Branch: contract.Branch, Commit: contract.Commit, ComposeFiles: contract.ComposeFiles,
		Services: serviceNames, TrafficService: contract.TrafficService,
		StableUpstream: contract.StableUpstream, InternalPort: contract.InternalPort,
		MigrationPaths: contract.MigrationPaths, Status: status, Blockers: contract.Blockers,
		DiscoveredAt: now, UpdatedAt: now,
	}); err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{
		Project: contract.Project, Status: status, Commit: contract.Commit,
		Fingerprint: contract.Fingerprint, Blockers: contract.Blockers,
	}
	if status == "blocked" {
		return result, nil
	}
	if !cfg.Deploy.Enabled {
		result.Status = "blocked"
		result.Blockers = []string{"automatic_deploy_disabled"}
		return result, nil
	}
	if cfg.GithubActions.ReleaseRepository == "" || cfg.GithubActions.ReleaseWorkflow == "" {
		result.Status = "blocked"
		result.Blockers = []string{"central_release_workflow_unconfigured"}
		return result, nil
	}
	releases, err := store.DeploymentReleases(ctx, contract.Project, 100)
	if err != nil {
		return SyncResult{}, err
	}
	for index := range releases {
		if releases[index].SourceCommit == contract.Commit {
			return continueRelease(ctx, contract, releases[index], store, client, runtime, now)
		}
	}
	imageRepository := "ghcr.io/" + strings.ToLower(contract.Repository)
	release, err := store.CreateDeploymentRelease(ctx, history.DeploymentRelease{
		ProjectName: contract.Project, ProjectRoot: contract.Root,
		ReleaseRepository: cfg.GithubActions.ReleaseRepository,
		ReleaseWorkflow:   cfg.GithubActions.ReleaseWorkflow,
		SourceRepository:  contract.Repository, SourceCommit: contract.Commit,
		ImageRepository: imageRepository, ContractFingerprint: contract.Fingerprint,
		State: "discovered", RequestedAt: now, UpdatedAt: now,
	}, history.OperationEvent{
		Type: "release_discovered", Summary: contract.Project + " release discovered",
		IdempotencyKey: "release-discovered", Notify: true,
	})
	if err != nil {
		return SyncResult{}, err
	}
	build := contract.Services[0]
	run, dispatchErr := client.DispatchRelease(ctx, githubactions.ReleaseDispatchRequest{
		ReleaseRepository: cfg.GithubActions.ReleaseRepository,
		Workflow:          cfg.GithubActions.ReleaseWorkflow, Ref: cfg.GithubActions.ReleaseRef,
		RequestID: release.OperationID, SourceRepository: contract.Repository,
		SourceCommit: contract.Commit, ImageRepository: imageRepository,
		BuildContext: build.BuildContext, Dockerfile: build.Dockerfile, BuildTarget: build.BuildTarget,
	})
	if dispatchErr != nil {
		release.State = "failed"
		release.UpdatedAt = now
		_ = store.TransitionDeploymentRelease(ctx, release, history.OperationEvent{
			Type: "release_build_failed", Summary: contract.Project + " release dispatch failed",
			IdempotencyKey: "release-dispatch-failed", Notify: true,
		})
		return SyncResult{}, fmt.Errorf("dispatch %s release: %w", contract.Project, dispatchErr)
	}
	release.State, release.GitHubRunID, release.RunURL = "building", run.ID, run.URL
	release.UpdatedAt = run.UpdatedAt
	if err := store.TransitionDeploymentRelease(ctx, release, history.OperationEvent{
		Type: "release_building", Summary: contract.Project + " release build started",
		IdempotencyKey: "release-run-created", Notify: true,
	}); err != nil {
		return SyncResult{}, err
	}
	return SyncResult{
		Project: contract.Project, Status: "building", Commit: contract.Commit,
		Fingerprint: contract.Fingerprint, RunURL: run.URL, Blockers: []string{},
	}, nil
}

func without(values []string, excluded string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != excluded {
			result = append(result, value)
		}
	}
	return result
}

// RuntimeDeployer owns exact-image pull, slots, health, traffic switch, and
// rollback. A nil runtime keeps a successful build ready without mutating
// Docker, which is useful for plan-only and notification-only installations.
type RuntimeDeployer interface {
	Deploy(context.Context, Contract, history.DeploymentRelease, time.Time) (history.DeploymentRelease, error)
	Rollback(context.Context, Contract, history.DeploymentRelease, time.Time) (history.DeploymentRelease, error)
}

func continueRelease(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	store *history.Store,
	client ReleaseClient,
	runtime RuntimeDeployer,
	now time.Time,
) (SyncResult, error) {
	result := SyncResult{
		Project: contract.Project, Status: release.State, Commit: contract.Commit,
		Fingerprint: contract.Fingerprint, RunURL: release.RunURL, Blockers: []string{},
	}
	if release.ContractFingerprint != contract.Fingerprint {
		result.Status = "blocked"
		result.Blockers = []string{"deployment_contract_changed"}
		return result, nil
	}
	switch release.State {
	case "building":
		run, err := client.GetRun(ctx, release.ReleaseRepository, release.GitHubRunID)
		if err != nil {
			return result, fmt.Errorf("read %s release run: %w", contract.Project, err)
		}
		if run.Status != "completed" {
			return result, nil
		}
		release.UpdatedAt = run.UpdatedAt
		if run.Conclusion != "success" {
			release.State = "failed"
			if err := store.TransitionDeploymentRelease(ctx, release, history.OperationEvent{
				Type: "release_build_failed", Summary: contract.Project + " release build failed",
				IdempotencyKey: "release-run-failed", Notify: true,
			}); err != nil {
				return result, err
			}
			result.Status = "failed"
			return result, nil
		}
		release.State = "ready"
		if err := store.TransitionDeploymentRelease(ctx, release, history.OperationEvent{
			Type: "release_ready", Summary: contract.Project + " exact release image is ready",
			IdempotencyKey: "release-run-succeeded", Notify: true,
		}); err != nil {
			return result, err
		}
		result.Status = "ready"
		if runtime == nil {
			return result, nil
		}
		fallthrough
	case "ready":
		if runtime == nil {
			return result, nil
		}
		deployed, err := runtime.Deploy(ctx, contract, release, now)
		if err != nil {
			switch deployed.State {
			case "blocked":
				result.Status = "blocked"
				result.Blockers = []string{"operator_decision_required"}
				return result, nil
			case "rolled_back":
				result.Status = "rolled_back"
				return result, err
			default:
				deployed.State = "failed"
				deployed.UpdatedAt = now
				_ = store.TransitionDeploymentRelease(ctx, deployed, history.OperationEvent{
					Type: "deploy_failed", Summary: contract.Project + " deployment failed",
					IdempotencyKey: "deploy-failed", Notify: true,
				})
				result.Status = "failed"
			}
			return result, err
		}
		result.Status = deployed.State
		return result, nil
	case "pulling", "starting", "healthy", "switching", "draining":
		result.Status = "blocked"
		result.Blockers = []string{"deployment_recovery_required"}
		return result, nil
	case "blocked":
		result.Blockers = []string{"operator_decision_required"}
		return result, nil
	default:
		return result, nil
	}
}
