package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
			return loadSelectedProjectConfig(parsedConfigPath, "reused", allowMigrationPrompt)
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
		return loadSelectedProjectConfig(localPath, "reused", allowMigrationPrompt)
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
	workspace, err := resolveAmbiguousWorkspace(discovery, configinit.Input{ScanOnly: true}, allowMigrationPrompt, promptChoice)
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("project detection is ambiguous: %w", err)
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
	return cfg, selection, nil
}

func loadSelectedProjectConfig(path, status string, allowMigrationPrompt bool) (*config.Config, scanConfigSelection, error) {
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
	return cfg, selection, nil
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
