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
		cfg, err := loadMachineConfig(parsedConfigPath, allowMigrationPrompt)
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
	cfg, selection, err := mergeProjectWithMachine(project, localPath, "created", allowMigrationPrompt)
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
	if explicitStack != "" && explicitStack != project.Workspace.Stack {
		return nil, scanConfigSelection{}, fmt.Errorf(
			"project at %s is already configured with workspace.stack %q; --stack only resolves first-run ambiguity\n\nTo change it: remove %s and re-run vuelta scan --stack %s, or edit workspace.stack directly in %s",
			root, project.Workspace.Stack, projectConfigName, explicitStack, path,
		)
	}
	driftWarning, detectedStacks, err := detectStackDrift(project.Workspace, root, allowMigrationPrompt)
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
	cfg, selection, err := mergeProjectWithMachine(project, path, status, allowMigrationPrompt)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	selection.OnboardingChanged = ignorePlan.Changed
	if ignorePlan.Changed {
		selection.ChangedFiles = []string{".gitignore"}
	}
	selection.DriftWarning = driftWarning
	selection.DetectedStacks = detectedStacks
	return cfg, selection, nil
}

// detectStackDrift re-detects stack signals in root and compares them against
// the persisted workspace.Stack. Any disagreement — the persisted stack no
// longer detected, or a newly ambiguous set of candidate stacks — is reported:
// as a non-fatal warning when interactive, or as a fail-closed error otherwise.
func detectStackDrift(workspace config.Workspace, root string, interactive bool) (string, []string, error) {
	discovery, err := configinit.Detect(root)
	if err != nil {
		return "", nil, fmt.Errorf("re-detect project stack signals for drift check: %w", err)
	}
	detectedStacks := append([]string(nil), discovery.Stacks...)
	if len(discovery.Stacks) == 1 && discovery.Stacks[0] == workspace.Stack {
		return "", detectedStacks, nil
	}
	detected := "none"
	if len(discovery.Stacks) > 0 {
		detected = strings.Join(discovery.Stacks, ", ")
	}
	message := fmt.Sprintf(
		"persisted workspace.stack %q no longer matches freshly detected project signals (detected: %s)",
		workspace.Stack, detected,
	)
	if !interactive {
		return "", nil, fmt.Errorf(
			"%s\n\nResolve: remove %s and re-run vuelta scan --stack <value>, or edit workspace.stack directly in %s",
			message, projectConfigName, root,
		)
	}
	return message + "; remove " + projectConfigName + " and re-run vuelta scan --stack <value>, or edit workspace.stack directly to update", detectedStacks, nil
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

func mergeProjectWithMachine(project *config.ProjectConfig, projectPath, status string, allowMigrationPrompt bool) (*config.Config, scanConfigSelection, error) {
	absoluteProjectPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("resolve project config path: %w", err)
	}
	projectPath = filepath.Clean(absoluteProjectPath)
	machinePath, err := defaultConfigPath()
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	return mergeProjectWithMachinePath(project, projectPath, status, machinePath, allowMigrationPrompt)
}

func mergeProjectWithMachinePath(project *config.ProjectConfig, projectPath, status, machinePath string, allowMigrationPrompt bool) (*config.Config, scanConfigSelection, error) {
	absoluteProjectPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("resolve project config path: %w", err)
	}
	projectPath = filepath.Clean(absoluteProjectPath)
	machine := configinit.NewConfig()
	if _, statErr := os.Lstat(machinePath); statErr == nil {
		machine, err = loadMachineConfig(machinePath, allowMigrationPrompt)
		if err != nil {
			return nil, scanConfigSelection{}, fmt.Errorf("load machine config %s: %w", machinePath, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, scanConfigSelection{}, fmt.Errorf("inspect machine config %s: %w", machinePath, statErr)
	}
	workspace, err := project.ResolvedWorkspace(projectPath)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	for _, registered := range machine.Workspaces {
		canonical, canonicalErr := canonicalDirectory(registered.Path)
		if canonicalErr == nil && canonical == workspace.Path {
			workspace.ToolchainProfile = registered.ToolchainProfile
			break
		}
	}
	machine.Workspaces = []config.Workspace{workspace}
	if err := machine.Validate(); err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("validate combined project and machine policy: %w", err)
	}
	return machine, scanConfigSelection{
		Path: projectPath, Scope: "project", Status: status, MachineConfig: machinePath,
	}, nil
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
