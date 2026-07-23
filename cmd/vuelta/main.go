// Command vuelta is a one-shot CLI: scan explicit targets, apply one reviewed
// snapshot inside a sandbox, and create immutable deploy candidates only when
// explicitly requested.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/deployworker"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/notify"
	"github.com/luckyfoxdesign/vuelta/internal/tasks"
)

const (
	exitOK       = 0
	exitFailure  = 1
	exitConfig   = 2
	exitSnapshot = 3
)

// version is set at build time with -ldflags when a release is produced.
var version = "dev"

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
	return newCLI(cliIO{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, lookup: os.LookupEnv}).run(args)
}

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
	for _, warning := range cfg.WorkspaceWarnings() {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fail(exitConfig, "%v", err)
	}
	return cfg, nil
}

func runConfig(args []string) error {
	if len(args) < 1 {
		return fail(exitConfig, "usage: vuelta config validate [--json] [config-path] | vuelta config init [--replace] [--yes] [config-path]")
	}
	switch args[0] {
	case "validate":
		return runConfigValidate(args[1:])
	case "init":
		return runConfigInit(args[1:])
	default:
		return fail(exitConfig, "usage: vuelta config validate [--json] [config-path] | vuelta config init [--replace] [--yes] [config-path]")
	}
}

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedFlag) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func runConfigInit(args []string) error {
	fs := flag.NewFlagSet("config init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	replace := fs.Bool("replace", false, "replace an existing config")
	yes := fs.Bool("yes", false, "confirm the displayed replacement diff")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting for confirmation")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	positional := fs.Args()
	if len(positional) > 1 {
		return fail(exitConfig, "usage: vuelta config init [--replace] [--yes] [config-path]")
	}
	path, err := configPath(positional)
	if err != nil {
		return err
	}
	plan, err := configinit.PlanConfigWrite(configinit.NewConfig(), path, *replace)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if plan.Exists && plan.Changed {
		fmt.Fprint(os.Stderr, plan.Diff(path))
		if !*yes {
			if *nonInteractive || !configinit.IsTerminal(os.Stdin) {
				return fail(exitConfig, "replacement requires confirmation; rerun with --replace --yes")
			}
			confirmed, confirmErr := promptConfirmation("Replace this config?")
			if confirmErr != nil {
				return fail(exitConfig, "%v", confirmErr)
			}
			if !confirmed {
				return fail(exitConfig, "config replacement cancelled")
			}
		}
	}
	if err := plan.Apply(path); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if plan.Exists {
		fmt.Printf("replaced validated config: %s\n", path)
	} else {
		fmt.Printf("created empty validated config: %s\n", path)
	}
	fmt.Println("scanner toolchains: detected defaults are built locally on first scan; update.toolchain_profiles is optional")
	fmt.Printf("Docker container execution: run `vuelta environment bootstrap --socket PATH --config %s`\n", path)
	return nil
}

func promptChoice(flag string, options []string) (string, error) {
	if len(options) > 0 {
		fmt.Fprintf(os.Stderr, "%s is required; detected options: %s\n", flag, strings.Join(options, ", "))
	}
	fmt.Fprintf(os.Stderr, "%s: ", flag)
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(value) == 0 {
		return "", fmt.Errorf("read %s: %w", flag, err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", flag)
	}
	return value, nil
}

func promptConfirmation(message string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", message)
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(value) == 0 {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func runScan(args []string) error {
	return executeScan(args)
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
	deployEndpoint, err := configuredDockerEndpoint(workerConfig.Docker, "production_worker.docker")
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	deployDocker := dockerexec.New(dockerexec.Options{Endpoint: deployEndpoint})
	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), time.Duration(workerConfig.OperationTimeoutSecond)*time.Second)
	defer verifyCancel()
	if err := deployDocker.Verify(verifyCtx); err != nil {
		return fail(exitEnv, "deploy Docker endpoint verification failed: %v", err)
	}
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
		Adapter:  deployworker.ComposeAdapter{Projects: composeProjects, Docker: deployDocker}, Notifier: notify.New(cfg.Notify), Projects: projects,
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

func workspaceByProject(cfg config.Config, project string) (config.Workspace, error) {
	for _, ws := range cfg.Workspaces {
		if config.WorkspaceName(ws) == project {
			return ws, nil
		}
	}
	return config.Workspace{}, fmt.Errorf("project %q is not configured", project)
}

func approvedCommit(ctx context.Context, ws config.Workspace, commit string) error {
	if err := gitexec.ValidateCommitSHA(commit); err != nil {
		return errors.New("commit must be a full, existing commit SHA")
	}
	if err := gitexec.ValidateRemoteName(ws.Remote); err != nil {
		return err
	}
	if err := gitexec.ValidateBranch(ws.Branch); err != nil {
		return err
	}
	if out, err := git(ctx, ws.Path, "rev-parse", "--verify", "--end-of-options", commit+"^{commit}"); err != nil || strings.TrimSpace(out) != commit {
		return errors.New("commit must be a full, existing commit SHA")
	}
	if _, err := git(ctx, ws.Path, "fetch", "--prune", ws.Remote); err != nil {
		return fmt.Errorf("fetch configured remote: %w", err)
	}
	if _, err := git(ctx, ws.Path, "merge-base", "--is-ancestor", commit, "refs/remotes/"+ws.Remote+"/"+ws.Branch); err != nil {
		return errors.New("commit is not merged into the configured protected branch")
	}
	return nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := gitexec.Output(ctx, dir, args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
