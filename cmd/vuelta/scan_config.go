package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

const projectConfigName = ".vuelta.yaml"

type scanConfigSelection struct {
	Path              string   `json:"path"`
	Scope             string   `json:"scope"`
	Status            string   `json:"status"`
	MachineConfig     string   `json:"machine_config,omitempty"`
	OnboardingChanged bool     `json:"onboarding_changed,omitempty"`
	ChangedFiles      []string `json:"changed_files,omitempty"`
	DriftWarning      string   `json:"drift_warning,omitempty"`
	DetectedStacks    []string `json:"detected_stacks,omitempty"`
}

// resolveAmbiguousWorkspace retries BuildWorkspace, resolving each
// *configinit.MissingValueError through chooseFlag when interactive; a
// non-interactive caller or a non-ambiguity error returns immediately.
func resolveAmbiguousWorkspace(discovery configinit.Discovery, input configinit.Input, interactive bool, chooseFlag func(flag string, options []string) (string, error)) (config.Workspace, error) {
	for {
		workspace, err := discovery.BuildWorkspace(input)
		if err == nil {
			return workspace, nil
		}
		var missing *configinit.MissingValueError
		if !interactive || !errors.As(err, &missing) {
			return config.Workspace{}, err
		}
		value, promptErr := chooseFlag(missing.Flag, missing.Options)
		if promptErr != nil {
			return config.Workspace{}, promptErr
		}
		setProjectInput(&input, missing.Flag, value)
	}
}

func selectScanConfiguration(options scanOptions, parsedConfigPath string) (*config.Config, scanConfigSelection, error) {
	allowMigrationPrompt := !options.jsonOutput && !options.nonInteractive && configinit.IsTerminal(os.Stdin)
	if options.explicitConfig || options.all || options.project != "" {
		projectFile := filepath.Base(parsedConfigPath) == projectConfigName
		if options.explicitConfig && !projectFile {
			var err error
			projectFile, err = config.IsProjectConfigFile(parsedConfigPath)
			if err != nil {
				return nil, scanConfigSelection{}, err
			}
		}
		if projectFile {
			return loadSelectedProjectConfig(parsedConfigPath, "reused", allowMigrationPrompt, options.stack)
		}
		cfg, err := loadMachineConfig(parsedConfigPath, false)
		if err != nil {
			return nil, scanConfigSelection{}, err
		}
		return cfg, scanConfigSelection{Path: parsedConfigPath, Scope: "machine", Status: "reused"}, nil
	}

	selectedPath := options.directory
	if selectedPath == "" {
		cwd, err := currentDirectory()
		if err != nil {
			return nil, scanConfigSelection{}, fmt.Errorf("resolve current directory: %w", err)
		}
		selectedPath = cwd
	}
	root, err := canonicalDirectory(selectedPath)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	localPath := filepath.Join(root, projectConfigName)
	_, statErr := os.Lstat(localPath)
	switch {
	case statErr == nil:
		return loadSelectedProjectConfig(localPath, "reused", allowMigrationPrompt, options.stack)
	case !errors.Is(statErr, os.ErrNotExist):
		return nil, scanConfigSelection{}, fmt.Errorf("inspect project config %s: %w", localPath, statErr)
	}

	if err := configinit.ValidateAutoCreateRoot(selectedPath, root, configinit.CurrentPathEnvironment()); err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf(
			"%w\n\nSpecify the project directory:\n  vuelta scan --directory /path/to/project",
			err,
		)
	}
	discovery, err := configinit.Detect(root)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	if len(discovery.Stacks) == 0 {
		return nil, scanConfigSelection{}, unsupportedProjectError(root)
	}
	workspace, err := resolveAmbiguousWorkspace(discovery, configinit.Input{Stack: options.stack, ScanOnly: true}, allowMigrationPrompt, promptChoice)
	if err != nil {
		return nil, scanConfigSelection{}, ambiguousStackError(err, root)
	}
	workspace.Path = "."
	project := &config.ProjectConfig{SchemaVersion: config.CurrentSchemaVersion, Workspace: workspace}
	plan, err := configinit.PlanProjectConfigWrite(project, localPath)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	ignorePlan, err := configinit.PlanProjectGitignore(root)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	ignorePath := filepath.Join(root, ".gitignore")
	if err := configinit.ApplyProjectOnboarding(&plan, localPath, ignorePlan, ignorePath); err != nil {
		return nil, scanConfigSelection{}, err
	}
	cfg, selection, err := mergeProjectWithMachine(project, localPath, "created")
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	selection.OnboardingChanged = true
	selection.ChangedFiles = []string{projectConfigName}
	if ignorePlan.Changed {
		selection.ChangedFiles = append(selection.ChangedFiles, ".gitignore")
	}
	selection.DetectedStacks = append([]string(nil), discovery.Stacks...)
	return cfg, selection, nil
}

func loadSelectedProjectConfig(path, status string, allowMigrationPrompt bool, explicitStack string) (*config.Config, scanConfigSelection, error) {
	project, err := config.LoadProject(path)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("resolve project config path: %w", err)
	}
	root, err := canonicalDirectory(filepath.Dir(absolute))
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	discovery, err := configinit.Detect(root)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("re-detect project stack signals for drift check: %w", err)
	}
	configUpdated := false
	if explicitStack != "" && explicitStack != project.Workspace.Stack {
		if containsStack(discovery.Stacks, project.Workspace.Stack) {
			return nil, scanConfigSelection{}, fmt.Errorf(
				"project at %s is already configured with workspace.stack %q, which remains freshly detected; --stack repairs genuine drift only",
				root, project.Workspace.Stack,
			)
		}
		if !containsStack(discovery.Stacks, explicitStack) {
			return nil, scanConfigSelection{}, fmt.Errorf(
				"--stack %q was not freshly detected in project %s\n\n%s",
				explicitStack, root, stackRepairGuidance(root, discovery.Stacks),
			)
		}
		repaired, repairErr := discovery.BuildWorkspace(configinit.Input{
			Name: project.Workspace.Name, Stack: explicitStack,
			Branch: project.Workspace.Branch, Remote: project.Workspace.Remote,
			ScanOnly: true,
		})
		if repairErr != nil {
			return nil, scanConfigSelection{}, fmt.Errorf("build freshly detected workspace for stack repair: %w", repairErr)
		}
		repaired.Path = "."
		repaired.Platform = project.Workspace.Platform
		repaired.Github = project.Workspace.Github
		plan, planErr := configinit.PlanProjectStackUpdate(path, repaired)
		if planErr != nil {
			return nil, scanConfigSelection{}, planErr
		}
		if applyErr := plan.Apply(path); applyErr != nil {
			return nil, scanConfigSelection{}, fmt.Errorf("persist repaired project stack: %w", applyErr)
		}
		project = &config.ProjectConfig{SchemaVersion: config.CurrentSchemaVersion, Workspace: repaired}
		status = "updated"
		configUpdated = plan.Changed
	}
	driftWarning, detectedStacks, err := detectStackDriftFromSignals(project.Workspace, root, discovery.Stacks, allowMigrationPrompt)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	ignorePlan, err := configinit.PlanProjectGitignore(root)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	if err := configinit.ApplyProjectOnboarding(nil, "", ignorePlan, filepath.Join(root, ".gitignore")); err != nil {
		return nil, scanConfigSelection{}, err
	}
	cfg, selection, err := mergeProjectWithMachine(project, path, status)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	selection.OnboardingChanged = configUpdated || ignorePlan.Changed
	if configUpdated {
		selection.ChangedFiles = append(selection.ChangedFiles, projectConfigName)
	}
	if ignorePlan.Changed {
		selection.ChangedFiles = append(selection.ChangedFiles, ".gitignore")
	}
	selection.DriftWarning = driftWarning
	selection.DetectedStacks = detectedStacks
	return cfg, selection, nil
}

// detectStackDrift re-detects stack signals in root and compares them against
// the persisted workspace.Stack. Additional signals are not drift while the
// selected stack remains present.
func detectStackDrift(workspace config.Workspace, root string, interactive bool) (string, []string, error) {
	discovery, err := configinit.Detect(root)
	if err != nil {
		return "", nil, fmt.Errorf("re-detect project stack signals for drift check: %w", err)
	}
	return detectStackDriftFromSignals(workspace, root, discovery.Stacks, interactive)
}

func detectStackDriftFromSignals(workspace config.Workspace, root string, stacks []string, interactive bool) (string, []string, error) {
	detectedStacks := append([]string(nil), stacks...)
	if containsStack(detectedStacks, workspace.Stack) {
		return "", detectedStacks, nil
	}
	detected := "none"
	if len(detectedStacks) > 0 {
		detected = strings.Join(detectedStacks, ", ")
	}
	message := fmt.Sprintf(
		"persisted workspace.stack %q is no longer among freshly detected project signals (detected: %s)\n\n%s",
		workspace.Stack, detected, stackRepairGuidance(root, detectedStacks),
	)
	if !interactive {
		return "", detectedStacks, errors.New(message)
	}
	return message, detectedStacks, nil
}

func containsStack(stacks []string, selected string) bool {
	for _, stack := range stacks {
		if stack == selected {
			return true
		}
	}
	return false
}

func stackRepairGuidance(root string, detectedStacks []string) string {
	if len(detectedStacks) == 0 {
		return "No supported replacement stack was detected. Restore a supported project manifest, lockfile, Dockerfile, or Compose file, then run vuelta scan again."
	}
	var guidance strings.Builder
	guidance.WriteString("Repair with a freshly detected stack (this atomically regenerates stack-dependent project policy):")
	for _, stack := range detectedStacks {
		fmt.Fprintf(
			&guidance,
			"\n  vuelta scan --directory %s --stack %s --no-input",
			quoteShellArgument(root), stack,
		)
	}
	return guidance.String()
}

func quoteShellArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// ambiguousStackError names the concrete non-interactive fix for a --stack
// ambiguity so a failed first-run onboarding never merely lists options. Only
// a *configinit.MissingValueError reflects an actual detection ambiguity;
// any other error (e.g. a cfg.Validate() failure after the stack was already
// resolved) is returned unwrapped so it surfaces under its own wording
// instead of being misattributed to detection.
func ambiguousStackError(err error, root string) error {
	var missing *configinit.MissingValueError
	if !errors.As(err, &missing) {
		return err
	}
	if missing.Flag == "--stack" {
		return fmt.Errorf(
			"%s\n\nResolve non-interactively:\n  vuelta scan --directory %s --stack <value>\n\nThe choice is persisted to workspace.stack in %s on first run",
			missing.Error(), root, projectConfigName,
		)
	}
	return fmt.Errorf("project detection is ambiguous: %w", err)
}

func mergeProjectWithMachine(project *config.ProjectConfig, projectPath, status string) (*config.Config, scanConfigSelection, error) {
	absoluteProjectPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("resolve project config path: %w", err)
	}
	projectPath = filepath.Clean(absoluteProjectPath)
	machinePath, err := defaultConfigPath()
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	return mergeProjectWithMachinePath(project, projectPath, status, machinePath)
}

// mergeProjectWithMachinePath builds the effective configuration for one
// exact project. Repository-owned workspace policy comes only from project;
// the machine file contributes global authority and, from a same-path legacy
// workspace entry, only the machine-owned toolchain selection. The machine
// file is loaded without migration prompts so project-local commands never
// rewrite it as a side effect.
func mergeProjectWithMachinePath(project *config.ProjectConfig, projectPath, status, machinePath string) (*config.Config, scanConfigSelection, error) {
	absoluteProjectPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("resolve project config path: %w", err)
	}
	projectPath = filepath.Clean(absoluteProjectPath)
	machine, machinePath, err := loadMachineAuthorityConfig(machinePath)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	workspace, err := project.ResolvedWorkspace(projectPath)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	// Legacy machine workspaces are lookup records for machine-owned
	// toolchain overrides only. None of their repository policy or warnings
	// enter the effective project-local configuration.
	for _, registered := range machine.Workspaces {
		canonical, canonicalErr := canonicalDirectory(registered.Path)
		if canonicalErr == nil && canonical == workspace.Path {
			workspace.ToolchainProfile = registered.ToolchainProfile
			break
		}
	}
	// The config-wide allowlist is a legacy workspace-policy fallback. Local
	// projects must carry their own allowlist in .vuelta.yaml; push mode stays
	// machine-owned.
	machine.Git.AllowedChangedPaths = nil
	machine.Workspaces = []config.Workspace{workspace}
	if err := machine.Validate(); err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("validate combined project and machine policy: %w", err)
	}
	return machine, scanConfigSelection{
		Path: projectPath, Scope: "project", Status: status, MachineConfig: machinePath,
	}, nil
}

func loadMachineAuthorityConfig(machinePath string) (*config.Config, string, error) {
	absoluteMachinePath, err := filepath.Abs(machinePath)
	if err != nil {
		return nil, "", fmt.Errorf("resolve machine config path: %w", err)
	}
	machinePath = filepath.Clean(absoluteMachinePath)
	machine := configinit.NewConfig()
	if _, statErr := os.Lstat(machinePath); statErr == nil {
		machine, err = loadMachineConfig(machinePath, false)
		if err != nil {
			return nil, "", fmt.Errorf("load machine config %s: %w", machinePath, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, "", fmt.Errorf("inspect machine config %s: %w", machinePath, statErr)
	}
	return machine, machinePath, nil
}

func unsupportedProjectError(root string) error {
	return fmt.Errorf(
		"vuelta did not find a supported project in %s.\n\nSpecify the project directory:\n  vuelta scan --directory /path/to/project\n\nThe project config will be created at:\n  /path/to/project/%s",
		root, projectConfigName,
	)
}

func projectHasGitMetadata(root string) bool {
	info, err := os.Lstat(filepath.Join(root, ".git"))
	return err == nil && info.Mode()&os.ModeSymlink == 0 && (info.IsDir() || info.Mode().IsRegular())
}
