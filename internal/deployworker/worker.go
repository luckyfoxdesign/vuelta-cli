// Package deployworker applies authenticated, immutable deployment candidates
// and restores the previously recorded digest when a rollout is unhealthy.
package deployworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/tasks"
)

const (
	StatusPending    = "pending"
	StatusRunning    = "running"
	StatusHealthy    = "healthy"
	StatusFailed     = "failed"
	StatusRolledBack = "rolled_back"
)

// Delivery is a candidate and the result of transport authentication. A
// worker refuses unauthenticated deliveries before it talks to the registry
// or deployment adapter.
type Delivery struct {
	Candidate     tasks.Candidate
	Authenticated bool
}

// Source returns candidates from one already-configured transport. Implementations
// must not fall back to mutable image tags or unverified delivery records.
type Source interface {
	Pending(context.Context) ([]Delivery, error)
}

// ArtifactVerifier validates the signed build manifest and its relationship
// to a candidate. It is called before the service is changed.
type ArtifactVerifier interface {
	Verify(context.Context, tasks.Candidate, Project) error
}

// Adapter is the narrowly scoped per-project production integration. It has
// no migration method by design: dependency rollouts never run database
// migrations automatically.
type Adapter interface {
	EnsureArtifact(context.Context, Project, string) error
	CurrentDigest(context.Context, Project) (string, error)
	Deploy(context.Context, Project, string) error
	Health(context.Context, Project) error
	Smoke(context.Context, Project) error
	Rollback(context.Context, Project, string) error
}

// Notifier receives a compact, secret-free lifecycle message. Full command
// output and configuration values are deliberately excluded from this API.
type Notifier interface {
	Send(string) error
}

// Project is an allowlisted deploy target. Name is matched exactly against the
// candidate; ImageRepository is supplied by the adapter configuration and is
// never accepted from the candidate.
type Project struct {
	Name            string
	ImageRepository string
}

// State is durable progress for one candidate. PreviousDigest is saved before
// the deploy operation so a restarted worker can roll back after a crash.
type State struct {
	CandidateID    string    `json:"candidate_id"`
	Project        string    `json:"project"`
	CommitSHA      string    `json:"commit_sha"`
	ImageDigest    string    `json:"image_digest"`
	ManifestDigest string    `json:"manifest_digest"`
	PreviousDigest string    `json:"previous_digest,omitempty"`
	Status         string    `json:"status"`
	UpdatedAt      time.Time `json:"updated_at"`
	FailureStage   string    `json:"failure_stage,omitempty"`
}

// Result is a safe summary of one worker decision.
type Result struct {
	CandidateID string
	Project     string
	Status      string
}

// Worker owns local state only. It never modifies a source checkout, .env,
// firewall, TLS, SSH configuration, or user data.
type Worker struct {
	Source           Source
	Verifier         ArtifactVerifier
	Adapter          Adapter
	Notifier         Notifier
	Projects         map[string]Project
	StateDir         string
	MaxCandidateAge  time.Duration
	OperationTimeout time.Duration
	Now              func() time.Time
}

func (w Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func (w Worker) maxAge() time.Duration {
	if w.MaxCandidateAge > 0 {
		return w.MaxCandidateAge
	}
	return 24 * time.Hour
}

func (w Worker) timeout() time.Duration {
	if w.OperationTimeout > 0 {
		return w.OperationTimeout
	}
	return 2 * time.Minute
}

// Run first recovers interrupted deployments, then processes each pending
// candidate under a per-project lock.
func (w Worker) Run(ctx context.Context) ([]Result, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	if err := w.Recover(ctx); err != nil {
		return nil, err
	}
	deliveries, err := w.Source.Pending(ctx)
	if err != nil {
		return nil, fmt.Errorf("read deployment candidates: %w", err)
	}
	results := make([]Result, 0, len(deliveries))
	for _, delivery := range deliveries {
		result, err := w.process(ctx, delivery)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// Recover changes an interrupted running rollout into a safe terminal state.
// It is intentionally conservative: a process crash is treated as a possible
// partial deploy and therefore triggers rollback before new work is accepted.
func (w Worker) Recover(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	states, err := w.allStates()
	if err != nil {
		return err
	}
	for _, state := range states {
		if state.Status != StatusRunning {
			continue
		}
		project, ok := w.Projects[state.Project]
		if !ok || state.PreviousDigest == "" {
			state.Status, state.FailureStage, state.UpdatedAt = StatusFailed, "recovery", w.now()
			if err := w.saveState(state); err != nil {
				return err
			}
			continue
		}
		unlock, err := w.lock(project.Name)
		if err != nil {
			return err
		}
		err = w.rollback(ctx, project, &state, "recovery")
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (w Worker) process(ctx context.Context, delivery Delivery) (Result, error) {
	candidate := delivery.Candidate
	if err := tasks.ValidateCandidate(candidate); err != nil {
		return w.rejected(candidate, "candidate")
	}
	if !delivery.Authenticated {
		return w.rejected(candidate, "authentication")
	}
	if candidate.Timestamp.After(w.now().Add(5*time.Minute)) || w.now().Sub(candidate.Timestamp) > w.maxAge() {
		return w.rejected(candidate, "freshness")
	}
	project, ok := w.Projects[candidate.Project]
	if !ok {
		return w.rejected(candidate, "project")
	}
	if _, exists, err := w.loadState(candidate.ID); err != nil {
		return Result{}, err
	} else if exists {
		return Result{CandidateID: candidate.ID, Project: candidate.Project, Status: StatusFailed}, nil
	}

	unlock, err := w.lock(project.Name)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if _, exists, err := w.loadState(candidate.ID); err != nil {
		return Result{}, err
	} else if exists {
		return Result{CandidateID: candidate.ID, Project: candidate.Project, Status: StatusFailed}, nil
	}
	if err := w.call(ctx, func(opCtx context.Context) error { return w.Verifier.Verify(opCtx, candidate, project) }); err != nil {
		return w.rejected(candidate, "manifest")
	}
	if err := w.call(ctx, func(opCtx context.Context) error {
		return w.Adapter.EnsureArtifact(opCtx, project, candidate.ImageDigest)
	}); err != nil {
		return w.rejected(candidate, "artifact")
	}
	previous, err := w.current(ctx, project)
	if err != nil {
		return w.rejected(candidate, "rollback_target")
	}
	state := State{
		CandidateID: candidate.ID, Project: candidate.Project, CommitSHA: candidate.CommitSHA,
		ImageDigest: candidate.ImageDigest, ManifestDigest: candidate.ManifestDigest,
		PreviousDigest: previous, Status: StatusRunning, UpdatedAt: w.now(),
	}
	if err := w.saveState(state); err != nil {
		return Result{}, err
	}
	if err := w.call(ctx, func(opCtx context.Context) error { return w.Adapter.Deploy(opCtx, project, candidate.ImageDigest) }); err != nil {
		return w.rollbackResult(ctx, project, &state, "deploy")
	}
	if err := w.call(ctx, func(opCtx context.Context) error { return w.Adapter.Health(opCtx, project) }); err != nil {
		return w.rollbackResult(ctx, project, &state, "health")
	}
	if err := w.call(ctx, func(opCtx context.Context) error { return w.Adapter.Smoke(opCtx, project) }); err != nil {
		return w.rollbackResult(ctx, project, &state, "smoke")
	}
	state.Status, state.UpdatedAt = StatusHealthy, w.now()
	if err := w.saveState(state); err != nil {
		return Result{}, err
	}
	w.notify(state)
	return Result{CandidateID: candidate.ID, Project: candidate.Project, Status: StatusHealthy}, nil
}

func (w Worker) rejected(candidate tasks.Candidate, stage string) (Result, error) {
	if !safeCandidateID(candidate.ID) {
		return Result{Project: candidate.Project, Status: StatusFailed}, nil
	}
	state := State{CandidateID: candidate.ID, Project: candidate.Project, CommitSHA: candidate.CommitSHA, ImageDigest: candidate.ImageDigest, ManifestDigest: candidate.ManifestDigest, Status: StatusFailed, FailureStage: stage, UpdatedAt: w.now()}
	if err := w.saveState(state); err != nil {
		return Result{}, err
	}
	w.notify(state)
	return Result{CandidateID: candidate.ID, Project: candidate.Project, Status: StatusFailed}, nil
}

func (w Worker) rollbackResult(ctx context.Context, project Project, state *State, stage string) (Result, error) {
	if err := w.rollback(ctx, project, state, stage); err != nil {
		return Result{}, err
	}
	return Result{CandidateID: state.CandidateID, Project: state.Project, Status: state.Status}, nil
}

func (w Worker) rollback(ctx context.Context, project Project, state *State, stage string) error {
	state.Status, state.FailureStage, state.UpdatedAt = StatusFailed, stage, w.now()
	if err := w.saveState(*state); err != nil {
		return err
	}
	if state.PreviousDigest == "" {
		w.notify(*state)
		return nil
	}
	if err := w.call(ctx, func(opCtx context.Context) error { return w.Adapter.Rollback(opCtx, project, state.PreviousDigest) }); err != nil {
		w.notify(*state)
		return fmt.Errorf("rollback candidate %s: %w", state.CandidateID, err)
	}
	if err := w.call(ctx, func(opCtx context.Context) error { return w.Adapter.Health(opCtx, project) }); err != nil {
		w.notify(*state)
		return fmt.Errorf("health check after rollback for %s: %w", state.CandidateID, err)
	}
	state.Status, state.UpdatedAt = StatusRolledBack, w.now()
	if err := w.saveState(*state); err != nil {
		return err
	}
	w.notify(*state)
	return nil
}

func (w Worker) current(ctx context.Context, project Project) (string, error) {
	var digest string
	err := w.call(ctx, func(opCtx context.Context) error {
		var err error
		digest, err = w.Adapter.CurrentDigest(opCtx, project)
		return err
	})
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return "", errors.New("adapter did not return an immutable rollback digest")
	}
	return digest, nil
}

func (w Worker) call(ctx context.Context, fn func(context.Context) error) error {
	opCtx, cancel := context.WithTimeout(ctx, w.timeout())
	defer cancel()
	return fn(opCtx)
}

func (w Worker) validate() error {
	if w.Source == nil || w.Verifier == nil || w.Adapter == nil {
		return errors.New("worker source, verifier, and adapter are required")
	}
	if w.StateDir == "" {
		return errors.New("worker state directory is required")
	}
	if len(w.Projects) == 0 {
		return errors.New("at least one production project is required")
	}
	for name, project := range w.Projects {
		if name == "" || name != project.Name || project.ImageRepository == "" {
			return errors.New("production projects require matching names and an allowlisted image repository")
		}
	}
	return w.ensureStateDir()
}

func (w Worker) ensureStateDir() error {
	if err := os.MkdirAll(w.StateDir, 0o700); err != nil {
		return fmt.Errorf("create deploy state directory: %w", err)
	}
	info, err := os.Lstat(w.StateDir)
	if err != nil {
		return fmt.Errorf("stat deploy state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("deploy state path must be a real directory")
	}
	if err := os.Chmod(w.StateDir, 0o700); err != nil {
		return fmt.Errorf("restrict deploy state directory: %w", err)
	}
	return nil
}

func (w Worker) statePath(id string) string {
	return filepath.Join(w.StateDir, "candidate-"+id+".json")
}

func safeCandidateID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

func (w Worker) loadState(id string) (State, bool, error) {
	if !safeCandidateID(id) {
		return State{}, false, errors.New("invalid deploy state candidate ID")
	}
	path := w.statePath(id)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("stat deploy state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return State{}, false, errors.New("deploy state must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, false, fmt.Errorf("read deploy state: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, false, fmt.Errorf("decode deploy state: %w", err)
	}
	if state.CandidateID != id {
		return State{}, false, errors.New("deploy state candidate ID does not match its filename")
	}
	return state, true, nil
}

func (w Worker) allStates() ([]State, error) {
	entries, err := os.ReadDir(w.StateDir)
	if err != nil {
		return nil, fmt.Errorf("read deploy state directory: %w", err)
	}
	var states []State
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), "candidate-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "candidate-"), ".json")
		state, ok, err := w.loadState(id)
		if err != nil {
			return nil, err
		}
		if ok {
			states = append(states, state)
		}
	}
	sort.Slice(states, func(i, j int) bool { return states[i].CandidateID < states[j].CandidateID })
	return states, nil
}

func (w Worker) saveState(state State) error {
	if !safeCandidateID(state.CandidateID) {
		return errors.New("invalid deploy state candidate ID")
	}
	if err := w.ensureStateDir(); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode deploy state: %w", err)
	}
	tmp, err := os.CreateTemp(w.StateDir, ".candidate-*.tmp")
	if err != nil {
		return fmt.Errorf("create deploy state temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict deploy state temp file: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write deploy state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync deploy state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close deploy state: %w", err)
	}
	if err := os.Rename(tmpName, w.statePath(state.CandidateID)); err != nil {
		return fmt.Errorf("commit deploy state: %w", err)
	}
	return os.Chmod(w.statePath(state.CandidateID), 0o600)
}

func (w Worker) lock(project string) (func(), error) {
	path := filepath.Join(w.StateDir, "lock-"+project)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open project deploy lock: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("restrict project deploy lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("deploy already running for project %q", project)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func (w Worker) notify(state State) {
	if w.Notifier == nil {
		return
	}
	// Only identifiers and state are sent; command output and configuration
	// are retained nowhere in this package.
	_ = w.Notifier.Send(fmt.Sprintf("vuelta deploy: project=%s candidate=%s status=%s image=%s", state.Project, state.CandidateID, state.Status, state.ImageDigest))
}
