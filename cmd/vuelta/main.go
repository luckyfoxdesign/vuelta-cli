// Command vuelta is a one-shot CLI: scan configured workspaces, update
// dependency versions inside sandboxed containers, run each project's tests,
// and create immutable deploy candidates only when explicitly requested.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/autofix"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/deployworker"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/logging"
	"github.com/luckyfoxdesign/vuelta/internal/notify"
	"github.com/luckyfoxdesign/vuelta/internal/pipeline"
	"github.com/luckyfoxdesign/vuelta/internal/tasks"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitConfig  = 2
)

type commandError struct {
	code int
	err  error
}

func (e commandError) Error() string { return e.err.Error() }
func (e commandError) Unwrap() error { return e.err }

func fail(code int, format string, args ...any) error {
	return commandError{code: code, err: fmt.Errorf(format, args...)}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vuelta:", err)
		var command commandError
		if errors.As(err, &command) {
			os.Exit(command.code)
		}
		os.Exit(exitConfig)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fail(exitConfig, usage)
	}
	switch args[0] {
	case "config":
		return runConfig(args[1:])
	case "run":
		return runPipeline(args[1:])
	case "scan":
		return runScan(args[1:])
	case "tasks":
		return runTasks(args[1:])
	case "deploy":
		return runDeploy(args[1:])
	default:
		return fail(exitConfig, "unknown command %q\n\n%s", args[0], usage)
	}
}

const usage = `usage: vuelta <command> [options] [config-path]

commands:
  run [--project NAME] [--dry-run] [config-path]
  scan [--project NAME] [config-path]
  config validate [config-path]
  tasks list [config-path]
  deploy enqueue --project NAME --commit SHA --image-digest SHA256 --manifest-digest SHA256 [config-path]
  deploy worker [config-path]`

func defaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config directory: %w", err)
	}
	return filepath.Join(dir, "vuelta", "config.yaml"), nil
}

func configPath(args []string) (string, error) {
	if len(args) > 1 {
		return "", fail(exitConfig, "expected at most one config path")
	}
	if len(args) == 1 {
		return args[0], nil
	}
	path, err := defaultConfigPath()
	if err != nil {
		return "", fail(exitConfig, "%v", err)
	}
	return path, nil
}

func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fail(exitConfig, "%v", err)
	}
	if warning, ok := cfg.PermissionWarning(); ok {
		fmt.Fprintln(os.Stderr, warning)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fail(exitConfig, "%v", err)
	}
	return cfg, nil
}

func runConfig(args []string) error {
	if len(args) < 1 || args[0] != "validate" {
		return fail(exitConfig, "usage: vuelta config validate [config-path]")
	}
	path, err := configPath(args[1:])
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	fmt.Printf("ok: %s is valid (%d workspace(s))\n", path, len(cfg.Workspaces))
	return nil
}

func runPipeline(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dryRun := fs.Bool("dry-run", false, "run without commit, push, or deploy candidate")
	project := fs.String("project", "", "run only one configured project")
	lockPath := fs.String("lock", "", "process lock path")
	jsonLogs := fs.Bool("json-logs", false, "write JSON log records")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := filterProject(cfg, *project); err != nil {
		return fail(exitConfig, "%v", err)
	}
	lock := *lockPath
	if lock == "" {
		lock, err = pipeline.DefaultLockPath()
		if err != nil {
			return fail(exitConfig, "resolve default lock path: %v", err)
		}
	}
	logger, err := logging.New(*jsonLogs)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	deps := pipeline.Deps{
		Sandbox: pipeline.BasicSandbox{}, Security: pipeline.DefaultSecurityGate{Scanner: vulnscan.Scanner{}, GitHub: githubalerts.Client{}},
		Autofix: autofix.Runner{}, Notifier: notify.New(cfg.Notify), Logger: logger,
	}
	summary, err := pipeline.Run(context.Background(), deps, *cfg, lock, *dryRun)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	updated, skipped, failed := summary.Counts()
	fmt.Printf("vuelta run finished: %d updated, %d skipped, %d failed\n", updated, skipped, failed)
	if failed > 0 {
		return fail(exitFailure, "%d workspace(s) failed", failed)
	}
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	project := fs.String("project", "", "scan only one configured project")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := filterProject(cfg, *project); err != nil {
		return fail(exitConfig, "%v", err)
	}
	gate := pipeline.DefaultSecurityGate{Scanner: vulnscan.Scanner{}, GitHub: githubalerts.Client{}}
	failed := 0
	for _, ws := range cfg.Workspaces {
		report, err := gate.Baseline(context.Background(), ws, *cfg)
		if err != nil {
			failed++
			fmt.Printf("%s: failed\n", filepath.Base(ws.Path))
			continue
		}
		fmt.Printf("%s: ok (%d finding(s))\n", filepath.Base(ws.Path), len(report.Findings))
	}
	if failed > 0 {
		return fail(exitFailure, "%d workspace(s) failed scan", failed)
	}
	return nil
}

func runTasks(args []string) error {
	if len(args) < 1 || args[0] != "list" {
		return fail(exitConfig, "usage: vuelta tasks list [config-path]")
	}
	path, err := configPath(args[1:])
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if cfg.DeployTask.Mode != "queue_file" {
		return fail(exitConfig, "tasks list is available only with deploy_task.mode=queue_file")
	}
	candidates, err := tasks.ListPending(cfg.DeployTask.QueueFile)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	for _, candidate := range candidates {
		fmt.Printf("%s %s %s %s\n", candidate.ID, candidate.Project, candidate.CommitSHA, candidate.Status)
	}
	return nil
}

func runDeploy(args []string) error {
	if len(args) < 1 {
		return fail(exitConfig, "usage: vuelta deploy enqueue ... | vuelta deploy worker [config-path]")
	}
	if args[0] == "worker" {
		return runDeployWorker(args[1:])
	}
	if args[0] != "enqueue" {
		return fail(exitConfig, "usage: vuelta deploy enqueue --project NAME --commit SHA --image-digest SHA256 --manifest-digest SHA256 [config-path]")
	}
	fs := flag.NewFlagSet("deploy enqueue", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	project := fs.String("project", "", "configured project name")
	commit := fs.String("commit", "", "already-approved commit SHA")
	image := fs.String("image-digest", "", "verified immutable OCI image digest")
	manifest := fs.String("manifest-digest", "", "verified immutable deploy manifest digest")
	if err := fs.Parse(args[1:]); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if *project == "" || *commit == "" || *image == "" || *manifest == "" {
		return fail(exitConfig, "--project, --commit, --image-digest, and --manifest-digest are required")
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	ws, err := workspaceByProject(*cfg, *project)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if err := approvedCommit(context.Background(), ws, *commit); err != nil {
		return fail(exitConfig, "%v", err)
	}
	creator := tasks.Creator{Config: cfg.DeployTask}
	candidate, created, err := creator.Create(context.Background(), tasks.CreateInput{
		Project: *project, CommitSHA: *commit, ImageDigest: *image, ManifestDigest: *manifest, RepoPath: ws.Path, Remote: ws.Remote,
	})
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if created {
		fmt.Printf("deploy candidate queued: %s\n", candidate.ID)
	} else {
		fmt.Printf("deploy candidate already queued: %s\n", candidate.ID)
	}
	return nil
}

func runDeployWorker(args []string) error {
	path, err := configPath(args)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if cfg.ProductionWorker == nil {
		return fail(exitConfig, "production_worker configuration is required for deploy worker")
	}
	workerConfig := cfg.ProductionWorker
	manifestKey, _ := base64.StdEncoding.DecodeString(workerConfig.ManifestPublicKey)
	var source deployworker.Source
	switch workerConfig.SourceMode {
	case "signed_queue_file":
		candidateKey, _ := base64.StdEncoding.DecodeString(workerConfig.CandidatePublicKey)
		source = deployworker.SignedQueueSource{Path: workerConfig.QueueFile, PublicKey: candidateKey}
	case "git_tag":
		source = deployworker.GitTagSource{
			Repository: workerConfig.GitMirror, Remote: workerConfig.GitRemote, ExpectedOrigin: workerConfig.GitExpectedOrigin,
			TagPrefix: workerConfig.GitTagPrefix, TrustedFingerprint: workerConfig.GitTrustedFingerprint,
		}
	default:
		return fail(exitConfig, "unsupported production_worker.source_mode %q", workerConfig.SourceMode)
	}
	projects := make(map[string]deployworker.Project, len(workerConfig.Projects))
	composeProjects := make(map[string]deployworker.ProjectCompose, len(workerConfig.Projects))
	for _, configured := range workerConfig.Projects {
		project := deployworker.Project{Name: configured.Name, ImageRepository: configured.ImageRepository}
		projects[project.Name] = project
		composeProjects[project.Name] = deployworker.ProjectCompose{
			Project: project, ComposeFile: configured.ComposeFile, Service: configured.Service,
			HealthURL: configured.HealthURL, SmokeURL: configured.SmokeURL,
		}
	}
	worker := deployworker.Worker{
		Source:   source,
		Verifier: deployworker.Ed25519ManifestVerifier{PublicKey: manifestKey, Load: deployworker.DigestFileLoader(workerConfig.ManifestDir)},
		Adapter:  deployworker.ComposeAdapter{Projects: composeProjects}, Notifier: notify.New(cfg.Notify), Projects: projects,
		StateDir: workerConfig.StateDir, MaxCandidateAge: time.Duration(workerConfig.MaxCandidateAgeMinutes) * time.Minute,
		OperationTimeout: time.Duration(workerConfig.OperationTimeoutSecond) * time.Second,
	}
	results, err := worker.Run(context.Background())
	if err != nil {
		return fail(exitFailure, "production deploy worker: %v", err)
	}
	for _, result := range results {
		fmt.Printf("deploy candidate %s %s %s\n", result.CandidateID, result.Project, result.Status)
	}
	return nil
}

func filterProject(cfg *config.Config, project string) error {
	if project == "" {
		return nil
	}
	ws, err := workspaceByProject(*cfg, project)
	if err != nil {
		return err
	}
	cfg.Workspaces = []config.Workspace{ws}
	return nil
}

func workspaceByProject(cfg config.Config, project string) (config.Workspace, error) {
	for _, ws := range cfg.Workspaces {
		if filepath.Base(ws.Path) == project {
			return ws, nil
		}
	}
	return config.Workspace{}, fmt.Errorf("project %q is not configured", project)
}

func approvedCommit(ctx context.Context, ws config.Workspace, commit string) error {
	if out, err := git(ctx, ws.Path, "rev-parse", "--verify", commit+"^{commit}"); err != nil || strings.TrimSpace(out) != commit {
		return errors.New("commit must be a full, existing commit SHA")
	}
	if _, err := git(ctx, ws.Path, "fetch", "--prune", ws.Remote); err != nil {
		return fmt.Errorf("fetch configured remote: %w", err)
	}
	if _, err := git(ctx, ws.Path, "merge-base", "--is-ancestor", commit, ws.Remote+"/"+ws.Branch); err != nil {
		return errors.New("commit is not merged into the configured protected branch")
	}
	return nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
