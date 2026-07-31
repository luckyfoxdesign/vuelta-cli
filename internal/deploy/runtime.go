package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/history"
	"github.com/luckyfoxdesign/vuelta/internal/pipeline"
)

// RunningSlot is the exact currently routed Vuelta-owned or adopted container.
type RunningSlot struct {
	Name       string
	Slot       string
	Digest     string
	Commit     string
	Container  string
	Labels     map[string]string
	NetworkIPs map[string]string
}

// CandidateSlot is one inactive exact-image container.
type CandidateSlot struct {
	Name      string
	Slot      string
	Digest    string
	Container string
}

// RuntimeDriver is the narrow infrastructure adapter. Arguments are derived
// from a validated contract; implementations never accept shell strings.
type RuntimeDriver interface {
	Preflight(context.Context, Contract) error
	PullExact(context.Context, Contract, history.DeploymentRelease) (string, error)
	Current(context.Context, Contract) (RunningSlot, error)
	ChangedMigrations(context.Context, Contract, string, string) ([]string, error)
	StartCandidate(context.Context, Contract, history.DeploymentRelease, string) (CandidateSlot, error)
	WaitHealthy(context.Context, Contract, CandidateSlot) error
	SwitchTraffic(context.Context, Contract, RunningSlot, CandidateSlot) error
	Smoke(context.Context, Contract, CandidateSlot) error
	ActivateCompanions(context.Context, Contract, history.DeploymentRelease, CandidateSlot) error
	RestoreTraffic(context.Context, Contract, RunningSlot) error
	Drain(context.Context, Contract, RunningSlot, time.Duration) error
	Stop(context.Context, Contract, RunningSlot) error
	RemoveCandidate(context.Context, Contract, CandidateSlot) error
}

// Runtime executes and durably records one blue-green state machine.
type Runtime struct {
	Driver       RuntimeDriver
	Store        *history.Store
	LockPath     string
	DrainTimeout time.Duration
	ApprovalTTL  time.Duration
}

// Deploy pulls, starts, verifies, switches, drains, and finalizes one exact
// release. Every externally visible stage is committed before the next stage.
func (r *Runtime) Deploy(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	now time.Time,
) (history.DeploymentRelease, error) {
	if r.Driver == nil || r.Store == nil {
		return release, errors.New("deployment runtime is not configured")
	}
	lockPath := r.LockPath
	if lockPath == "" {
		lockPath = filepath.Join(filepath.Dir(r.Store.Path()), "deploy.lock")
	}
	lock, err := pipeline.AcquireProcessLock(lockPath)
	if err != nil {
		return release, fmt.Errorf("another deployment is active: %w", err)
	}
	defer func() { _ = lock.Release() }()
	if err := r.Driver.Preflight(ctx, contract); err != nil {
		return release, fmt.Errorf("deployment preflight: %w", err)
	}

	current, err := r.Driver.Current(ctx, contract)
	if err != nil {
		return release, fmt.Errorf("inspect current deployment: %w", err)
	}
	release.PreviousDigest, release.PreviousSlot = current.Digest, current.Slot
	release.State, release.StartedAt, release.UpdatedAt = "pulling", &now, now
	if err := r.transition(ctx, release, "deploy_started", contract.Project+" deploy started", "deploy-started", true); err != nil {
		return release, err
	}
	digest, err := r.Driver.PullExact(ctx, contract, release)
	if err != nil {
		return release, fmt.Errorf("pull exact candidate: %w", err)
	}
	release.CandidateDigest = digest

	changes, err := r.Driver.ChangedMigrations(ctx, contract, current.Commit, release.SourceCommit)
	if err != nil {
		return release, fmt.Errorf("compare migration paths: %w", err)
	}
	if len(changes) > 0 {
		blocked, blockErr := r.requireMigrationApproval(ctx, contract, release, changes, now)
		if blockErr != nil {
			return blocked, blockErr
		}
		return blocked, errors.New("reviewed migration workflow is unavailable for an automatically discovered project")
	}

	release.CandidateSlot = oppositeSlot(current.Slot)
	release.State, release.UpdatedAt = "starting", time.Now().UTC()
	if err := r.transition(ctx, release, "candidate_starting", contract.Project+" candidate starting", "candidate-starting", false); err != nil {
		return release, err
	}
	candidate, err := r.Driver.StartCandidate(ctx, contract, release, release.CandidateSlot)
	if err != nil {
		return release, fmt.Errorf("start candidate: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = r.Driver.RemoveCandidate(context.Background(), contract, candidate)
		}
	}()
	if err := r.Driver.WaitHealthy(ctx, contract, candidate); err != nil {
		return release, fmt.Errorf("candidate health: %w", err)
	}
	release.State, release.UpdatedAt = "healthy", time.Now().UTC()
	if err := r.transition(ctx, release, "candidate_healthy", contract.Project+" candidate healthy", "candidate-healthy", false); err != nil {
		return release, err
	}
	if err := r.Driver.SwitchTraffic(ctx, contract, current, candidate); err != nil {
		return release, fmt.Errorf("switch traffic: %w", err)
	}
	switched := time.Now().UTC()
	release.State, release.SwitchedAt, release.UpdatedAt = "switching", &switched, switched
	if err := r.transition(ctx, release, "traffic_switched", contract.Project+" traffic switched", "traffic-switched", true); err != nil {
		_ = r.Driver.RestoreTraffic(ctx, contract, current)
		return release, err
	}
	if err := r.Driver.Smoke(ctx, contract, candidate); err != nil {
		restoreErr := r.Driver.RestoreTraffic(ctx, contract, current)
		if restoreErr == nil {
			restoreErr = r.Driver.Smoke(ctx, contract, CandidateSlot{
				Name: current.Name, Slot: current.Slot, Digest: current.Digest, Container: current.Container,
			})
		}
		release.State, release.UpdatedAt = "rolled_back", time.Now().UTC()
		_ = r.transition(ctx, release, "rollback_completed", contract.Project+" rollback completed", "rollback-completed", true)
		if restoreErr != nil {
			return release, errors.Join(fmt.Errorf("candidate smoke: %w", err), fmt.Errorf("restore previous traffic: %w", restoreErr))
		}
		return release, fmt.Errorf("candidate smoke failed and previous traffic was restored: %w", err)
	}
	if err := r.Driver.ActivateCompanions(ctx, contract, release, candidate); err != nil {
		restoreErr := r.Driver.RestoreTraffic(ctx, contract, current)
		release.State, release.UpdatedAt = "rolled_back", time.Now().UTC()
		_ = r.transition(ctx, release, "rollback_completed", contract.Project+" rollback completed", "companion-rollback", true)
		if restoreErr != nil {
			return release, errors.Join(fmt.Errorf("activate companion services: %w", err), restoreErr)
		}
		return release, fmt.Errorf("companion activation failed and previous traffic was restored: %w", err)
	}
	release.State, release.UpdatedAt = "draining", time.Now().UTC()
	if err := r.transition(ctx, release, "deploy_draining", contract.Project+" previous slot draining", "deploy-draining", false); err != nil {
		return release, err
	}
	drain := r.DrainTimeout
	if drain <= 0 {
		drain = 30 * time.Second
	}
	if current.Container != "" {
		if err := r.Driver.Drain(ctx, contract, current, drain); err != nil {
			return release, fmt.Errorf("drain previous slot: %w", err)
		}
		if err := r.Driver.Stop(ctx, contract, current); err != nil {
			return release, fmt.Errorf("stop previous slot: %w", err)
		}
	}
	completed := time.Now().UTC()
	release.State, release.CompletedAt, release.UpdatedAt = "deployed", &completed, completed
	if err := r.transition(ctx, release, "deploy_completed", contract.Project+" deployment completed", "deploy-completed", true); err != nil {
		return release, err
	}
	cleanup = false
	return release, nil
}

// Rollback restores the recorded previous slot and checks it before removing
// the failed candidate.
func (r *Runtime) Rollback(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	now time.Time,
) (history.DeploymentRelease, error) {
	if r.Driver == nil || r.Store == nil {
		return release, errors.New("deployment runtime is not configured")
	}
	if release.PreviousDigest == "" || release.PreviousSlot == "" {
		return release, errors.New("recorded previous immutable slot is unavailable")
	}
	lockPath := r.LockPath
	if lockPath == "" {
		lockPath = filepath.Join(filepath.Dir(r.Store.Path()), "deploy.lock")
	}
	lock, err := pipeline.AcquireProcessLock(lockPath)
	if err != nil {
		return release, fmt.Errorf("another deployment is active: %w", err)
	}
	defer func() { _ = lock.Release() }()
	previous := RunningSlot{
		Name: contract.Project, Slot: release.PreviousSlot,
		Digest: release.PreviousDigest, Container: slotContainer(contract, release.PreviousSlot),
	}
	if err := r.Driver.RestoreTraffic(ctx, contract, previous); err != nil {
		return release, err
	}
	if err := r.Driver.Smoke(ctx, contract, CandidateSlot{
		Name: previous.Name, Slot: previous.Slot, Digest: previous.Digest, Container: previous.Container,
	}); err != nil {
		return release, err
	}
	release.State, release.UpdatedAt = "rolled_back", now
	if err := r.transition(ctx, release, "rollback_completed", contract.Project+" rollback completed", "manual-rollback", true); err != nil {
		return release, err
	}
	return release, nil
}

func (r *Runtime) requireMigrationApproval(
	ctx context.Context,
	contract Contract,
	release history.DeploymentRelease,
	changes []string,
	now time.Time,
) (history.DeploymentRelease, error) {
	subject := struct {
		Project    string   `json:"project"`
		Commit     string   `json:"commit"`
		Digest     string   `json:"digest"`
		Migrations []string `json:"migrations"`
	}{
		Project: contract.Project, Commit: release.SourceCommit,
		Digest: release.CandidateDigest, Migrations: changes,
	}
	data, err := json.Marshal(subject)
	if err != nil {
		return release, err
	}
	digest := sha256.Sum256(data)
	fingerprint := hex.EncodeToString(digest[:])
	approval, err := r.Store.ApprovalByFingerprint(
		ctx, release.OperationID, "migration", fingerprint, now,
	)
	if err != nil {
		return release, err
	}
	if approval != nil && approval.Status == "approved" {
		release.State, release.UpdatedAt = "blocked", now
		if err := r.transition(
			ctx, release, "migration_workflow_unavailable",
			contract.Project+" reviewed migration workflow is unavailable",
			"migration-workflow-unavailable-"+fingerprint, true,
		); err != nil {
			return release, err
		}
		return release, errors.New("reviewed migration workflow is unavailable for the approved release")
	}
	if approval == nil {
		ttl := r.ApprovalTTL
		if ttl <= 0 {
			ttl = time.Hour
		}
		_, err = r.Store.CreateApprovalRequest(ctx, history.ApprovalRequest{
			OperationID: release.OperationID, Type: "migration",
			SubjectFingerprint: fingerprint, SubjectSummary: string(data),
			CreatedAt: now, ExpiresAt: now.Add(ttl),
		}, history.OperationEvent{
			Type:           "migration_approval_required",
			Summary:        contract.Project + " migration approval required",
			IdempotencyKey: "migration-approval-" + fingerprint, Notify: true,
		})
		if err != nil {
			return release, err
		}
	}
	release.State, release.UpdatedAt = "blocked", now
	if err := r.transition(ctx, release, "deploy_blocked", contract.Project+" deployment blocked by migrations", "migration-blocked-"+fingerprint, false); err != nil {
		return release, err
	}
	return release, errors.New("exact migration approval is required")
}

func (r *Runtime) transition(
	ctx context.Context,
	release history.DeploymentRelease,
	eventType, summary, key string,
	notify bool,
) error {
	return r.Store.TransitionDeploymentRelease(ctx, release, history.OperationEvent{
		Type: eventType, Summary: summary, IdempotencyKey: key, Notify: notify,
	})
}

func oppositeSlot(current string) string {
	if current == "blue" {
		return "green"
	}
	return "blue"
}

func slotContainer(contract Contract, slot string) string {
	return "vuelta-" + contract.Project + "-" + slot + "-" + contract.TrafficService
}
