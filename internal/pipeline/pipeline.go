// Package pipeline applies one selected workspace snapshot through preflight,
// sandbox, security gates, update, diff/allowlist checks, tests, optional
// autofix, commit, push, and notification. The runner uses the hardened
// isolation provided by sandbox, updater, and testrunner.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/gitops"
	"github.com/luckyfoxdesign/vuelta/internal/logging"
	"github.com/luckyfoxdesign/vuelta/internal/notify"
	"github.com/luckyfoxdesign/vuelta/internal/scanner"
	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

// Sandbox prepares and tears down the one-off, tracked-files-only working
// copy used for running the updater and tests. The implementation creates a
// tracked-files-only archive; the updater and testrunner enforce container
// policy around that copy.
type Sandbox interface {
	Prepare(ctx context.Context, repoPath, baseSHA string) (dir string, cleanup func() error, err error)
}

// Report is a CVE/advisory scan result. Ran distinguishes "scanned, found
// nothing" from "not run at all" so a stub SecurityGate can never be
// mistaken for a clean scan.
type Report struct {
	Findings []string
	Ran      bool
	// details is intentionally private: webhook/Telegram and commit code get
	// only identifier references, never package paths, scanner output, or logs.
	details []vulnscan.Finding
}

// SecurityGate runs the pre-update baseline and post-update CVE/GitHub
// Dependabot checks (part C; pipeline steps 2 and 5).
type SecurityGate interface {
	Baseline(ctx context.Context, ws config.Workspace, cfg config.Config) (Report, error)
	PostCheck(ctx context.Context, workDir string, ws config.Workspace, cfg config.Config, baseline Report) (Report, error)
}

// Autofixer runs a single bounded `claude -p` attempt against a failed
// test run (part C, pipeline step 7). It is only invoked when
// autofix.enabled is true.
type Autofixer interface {
	Attempt(ctx context.Context, sandboxDir, testOutput, allowedDiff string, cfg config.AutofixConfig) (attempted bool, err error)
}

// Deps wires the pipeline to its stage implementations.
type Deps struct {
	Sandbox  Sandbox
	Security SecurityGate
	Autofix  Autofixer
	Notifier *notify.Notifier
	Logger   *logging.Logger
	Docker   dockerexec.Runner
	// Now returns the current time; defaults to time.Now when nil. Tests
	// override it for deterministic branch names and commit messages.
	Now func() time.Time
	// ResolveUpdater picks the Updater for a workspace; defaults to
	// updater.Resolve when nil. Tests override it to avoid shelling out to
	// a real docker daemon.
	ResolveUpdater func(ws config.Workspace, cfg config.Config) (updater.Updater, error)
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) resolveUpdater(ws config.Workspace, cfg config.Config) (updater.Updater, error) {
	if d.ResolveUpdater != nil {
		return d.ResolveUpdater(ws, cfg)
	}
	return updater.ResolveWithDocker(ws, cfg, d.docker())
}

func (d Deps) docker() dockerexec.Runner {
	if d.Docker != nil {
		return d.Docker
	}
	return dockerexec.Default()
}

// RunWorkspace executes pipeline steps 1-10 for a single workspace. It
// never returns a Go error: every failure mode becomes a
// notify.ProjectResult with Status "failed" so Run can keep going with the
// next workspace (part B §7 closing note: summary counts updated/skipped/failed).
func RunWorkspace(ctx context.Context, deps Deps, cfg config.Config, ws config.Workspace, dryRun bool) (output notify.ProjectResult) {
	now := deps.now()
	label := config.WorkspaceName(ws)

	// Step 1: preflight.
	if err := scanner.CheckToolsWithDocker(deps.docker()); err != nil {
		return failResult(label, "preflight", err)
	}
	pre, err := scanner.Preflight(ctx, ws)
	if err != nil {
		return failResult(label, "preflight", err)
	}
	project := label
	audit := logging.AuditRecord{Project: project}
	defer func() {
		if deps.Logger == nil {
			return
		}
		audit.PostSecurity = output.CVERefs
		audit.AlertIDs = output.CVERefs
		_ = deps.Logger.Audit(audit)
	}()
	if pre.Skip != scanner.SkipNone {
		return notify.ProjectResult{Project: project, Status: "skipped", Reason: string(pre.Skip)}
	}

	baseSHA, err := gitops.FetchAndBaseSHA(ctx, pre.CanonicalPath, ws.Remote, ws.Branch)
	if err != nil {
		return failResult(project, "preflight fetch", err)
	}
	audit.BaseSHA = baseSHA

	sandboxDir, sandboxCleanup, err := deps.Sandbox.Prepare(ctx, pre.CanonicalPath, baseSHA)
	if err != nil {
		return failResult(project, "sandbox prepare", err)
	}
	defer func() { warnCleanupFailure(fmt.Sprintf("sandbox cleanup for %s", project), sandboxCleanup()) }()

	landingDir, landingCleanup, err := gitops.NewLandingCopy(ctx, pre.CanonicalPath, baseSHA)
	if err != nil {
		return failResult(project, "landing copy", err)
	}
	defer func() { warnCleanupFailure(fmt.Sprintf("landing copy cleanup for %s", project), landingCleanup()) }()

	// Step 2: security baseline.
	baseline, err := deps.Security.Baseline(ctx, ws, cfg)
	if err != nil {
		return failResult(project, "security baseline", err)
	}
	audit.PreSecurity = baseline.Findings

	// Step 3: update versions.
	upd, err := deps.resolveUpdater(ws, cfg)
	if err != nil {
		return failResult(project, "resolve updater", err)
	}
	changed, err := upd.Update(ctx, sandboxDir)
	if err != nil {
		return failResult(project, "update", err)
	}
	if !changed {
		return notify.ProjectResult{Project: project, Status: "skipped", Reason: "no dependency changes", CVERefs: baseline.Findings}
	}

	// Step 4: verify the change touches only allowlisted paths.
	if err := gitops.SyncTree(sandboxDir, landingDir); err != nil {
		return failResult(project, "sync sandbox to landing copy", err)
	}
	if err := gitops.DiffCheck(ctx, landingDir, cfg.AllowedChangedPaths(ws)); err != nil {
		return failResult(project, "diff policy", err)
	}
	if changedPaths, err := gitops.ChangedPaths(ctx, landingDir); err != nil {
		return failResult(project, "audit changed paths", err)
	} else {
		audit.ChangedPaths = changedPaths
	}

	// Step 5: security post-check.
	post, err := deps.Security.PostCheck(ctx, sandboxDir, ws, cfg, baseline)
	if err != nil {
		return failResult(project, "security post-check", err)
	}

	// Step 6: tests, with one optional autofix retry (step 7).
	testTimeout := time.Duration(ws.Test.TimeoutMinutes) * time.Minute
	result, err := testrunner.RunWithDocker(ctx, deps.docker(), sandboxDir, ws.Test, testTimeout)
	if err != nil {
		return failResult(project, "test run", err)
	}
	autofixApplied := false
	if !result.Passed && cfg.Autofix.Enabled {
		allowedDiff, diffErr := gitops.AllowlistedDiff(ctx, landingDir, cfg.AllowedChangedPaths(ws))
		if diffErr != nil {
			return failResult(project, "autofix diff policy", diffErr)
		}
		attempted, aErr := deps.Autofix.Attempt(ctx, sandboxDir, result.Output, allowedDiff, cfg.Autofix)
		if aErr != nil {
			return failResult(project, "autofix", aErr)
		}
		if attempted {
			autofixApplied = true
			result, err = testrunner.RunWithDocker(ctx, deps.docker(), sandboxDir, ws.Test, testTimeout)
			if err != nil {
				return failResult(project, "test run after autofix", err)
			}
			if result.Passed {
				return finishAfterAutofix(ctx, project, ws, cfg, sandboxDir, landingDir, now, post, dryRun, &audit)
			}
		}
	}
	if !result.Passed {
		return notify.ProjectResult{Project: project, Status: "failed", Reason: "tests failed", CVERefs: post.Findings}
	}

	if dryRun {
		return dryRunResult(project, post, autofixApplied)
	}

	// Step 8: commit.
	if err := gitops.VerifyBaseSHAUnchanged(ctx, pre.CanonicalPath, ws.Remote, ws.Branch, baseSHA); err != nil {
		return failResult(project, "base SHA changed", err)
	}
	summary := gitops.CommitSummary{Date: now, CVERefs: post.Findings}
	if err := gitops.Commit(ctx, landingDir, cfg.AllowedChangedPaths(ws), summary); err != nil {
		return failResult(project, "commit", err)
	}
	if commitSHA, err := gitops.HeadSHA(ctx, landingDir); err != nil {
		return failResult(project, "resolve commit SHA", err)
	} else {
		audit.CommitSHA = commitSHA
	}

	// Step 9: push.
	branch, err := gitops.Push(ctx, landingDir, ws, cfg.Git, project, now)
	if err != nil {
		return failResult(project, "push", err)
	}

	return notify.ProjectResult{Project: project, Status: "updated", Branch: branch, CVERefs: post.Findings}
}

// finishAfterAutofix re-syncs the autofix's edits from the sandbox into the
// landing copy and always pushes to the fixed autofix review branch,
// regardless of git.push_mode: an AI-touched change never goes straight to
// a protected branch (part C: "Автоматический push в основную ветку
// разрешён только для чистых lock-file апдейтов без вмешательства ИИ").
func finishAfterAutofix(ctx context.Context, project string, ws config.Workspace, cfg config.Config, sandboxDir, landingDir string, now time.Time, post Report, dryRun bool, audit *logging.AuditRecord) notify.ProjectResult {
	if err := gitops.SyncTree(sandboxDir, landingDir); err != nil {
		return failResult(project, "sync sandbox to landing copy after autofix", err)
	}
	if err := gitops.DiffCheck(ctx, landingDir, cfg.AllowedChangedPaths(ws)); err != nil {
		return failResult(project, "diff policy after autofix", err)
	}
	if changedPaths, err := gitops.ChangedPaths(ctx, landingDir); err != nil {
		return failResult(project, "audit changed paths after autofix", err)
	} else {
		audit.ChangedPaths = changedPaths
	}
	if dryRun {
		return dryRunResult(project, post, true)
	}
	summary := gitops.CommitSummary{Date: now, CVERefs: post.Findings}
	if err := gitops.Commit(ctx, landingDir, cfg.AllowedChangedPaths(ws), summary); err != nil {
		return failResult(project, "autofix commit", err)
	}
	if commitSHA, err := gitops.HeadSHA(ctx, landingDir); err != nil {
		return failResult(project, "resolve autofix commit SHA", err)
	} else {
		audit.CommitSHA = commitSHA
	}
	branch := gitops.AutofixBranch(project, now)
	if err := gitops.PushBranch(ctx, landingDir, ws.Remote, branch); err != nil {
		return failResult(project, "autofix push", err)
	}
	return notify.ProjectResult{
		Project:        project,
		Status:         "updated",
		Branch:         branch,
		Reason:         "autofix applied: review required",
		AutofixApplied: true,
		CVERefs:        post.Findings,
	}
}

func dryRunResult(project string, post Report, autofixApplied bool) notify.ProjectResult {
	return notify.ProjectResult{
		Project:        project,
		Status:         "dry_run",
		Reason:         "dry-run: commit/push skipped",
		AutofixApplied: autofixApplied,
		CVERefs:        post.Findings,
	}
}

func failResult(project, stage string, err error) notify.ProjectResult {
	// Error strings from scanners, Docker, and tests can contain untrusted
	// output. Keep notification results terse; the local private log owns
	// diagnostic detail.
	status := "failed"
	if strings.HasPrefix(stage, "security") {
		status = "blocked"
	}
	return notify.ProjectResult{Project: project, Status: status, Reason: stage}
}

// warnCleanupFailure reports a best-effort cleanup failure to stderr rather
// than discarding it. It never fails the run that's already succeeded or
// failed on its own terms, but a leaked sandbox dir or a git worktree that
// failed to detach from the user's real repo is exactly the kind of thing
// an operator needs to see, not something to silently swallow.
func warnCleanupFailure(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "vuelta: warning: %s: %v\n", what, err)
	}
}

// DefaultLockPath is where Run acquires its process lock when the caller
// does not override it, next to the default config location.
func DefaultLockPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vuelta", "vuelta.lock"), nil
}

// Run executes RunWorkspace for every configured workspace, sequentially
// and under a process lock, sending a per-project notification as each
// workspace finishes and a final run summary at the end (part B §7 closing
// note). --dry-run runs steps 1-7 for every workspace but never commits,
// pushes, or queues a deploy candidate.
func Run(ctx context.Context, deps Deps, cfg config.Config, lockPath string, dryRun bool) (notify.RunSummary, error) {
	lock, err := AcquireProcessLock(lockPath)
	if err != nil {
		return notify.RunSummary{}, err
	}
	defer func() { warnCleanupFailure(fmt.Sprintf("process lock release (%s)", lockPath), lock.Release()) }()

	summary := notify.RunSummary{Started: deps.now()}
	for _, ws := range cfg.Workspaces {
		result := RunWorkspace(ctx, deps, cfg, ws, dryRun)
		summary.Results = append(summary.Results, result)
		if deps.Notifier != nil {
			_ = deps.Notifier.SendProjectResult(ctx, result)
		}
		if deps.Logger != nil {
			_ = deps.Logger.Event("INFO", "project complete", map[string]string{
				"project": result.Project, "status": result.Status, "reason": result.Reason,
			})
		}
	}
	summary.Finished = deps.now()
	if deps.Notifier != nil {
		_ = deps.Notifier.SendRunSummary(ctx, summary)
	}
	return summary, nil
}
