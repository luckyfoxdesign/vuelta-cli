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
	Path          string `json:"path"`
	Scope         string `json:"scope"`
	Status        string `json:"status"`
	MachineConfig string `json:"machine_config,omitempty"`
}

func selectScanConfiguration(options scanOptions, parsedConfigPath string) (*config.Config, scanConfigSelection, error) {
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
			return loadSelectedProjectConfig(parsedConfigPath, "reused")
		}
		cfg, err := config.Load(parsedConfigPath)
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
		return loadSelectedProjectConfig(localPath, "reused")
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
	workspace, err := discovery.BuildWorkspace(configinit.Input{ScanOnly: true})
	if err != nil {
		return nil, scanConfigSelection{}, fmt.Errorf("project detection is ambiguous: %w", err)
	}
	workspace.Path = "."
	project := &config.ProjectConfig{SchemaVersion: config.CurrentSchemaVersion, Workspace: workspace}
	plan, err := configinit.PlanProjectConfigWrite(project, localPath)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	if err := plan.Apply(localPath); err != nil {
		return nil, scanConfigSelection{}, err
	}
	return mergeProjectWithMachine(project, localPath, "created")
}

func loadSelectedProjectConfig(path, status string) (*config.Config, scanConfigSelection, error) {
	project, err := config.LoadProject(path)
	if err != nil {
		return nil, scanConfigSelection{}, err
	}
	return mergeProjectWithMachine(project, path, status)
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
	machine := configinit.NewConfig()
	if _, statErr := os.Lstat(machinePath); statErr == nil {
		machine, err = config.Load(machinePath)
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
