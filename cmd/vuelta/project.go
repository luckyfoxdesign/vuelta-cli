package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

type jsonCommandError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type jsonCommandEnvelope struct {
	Format   int                `json:"format"`
	Command  string             `json:"command"`
	Results  any                `json:"results"`
	Summary  any                `json:"summary"`
	Warnings []string           `json:"warnings"`
	Errors   []jsonCommandError `json:"errors"`
}

type projectListResult struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func runConfigValidate(args []string) error {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := fs.Bool("json", false, "write the versioned JSON envelope")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "invalid_invocation", err, nil)
	}
	cfg, loadErr := config.Load(path)
	if loadErr != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "config_unreadable", fail(exitConfig, "%v", loadErr), nil)
	}
	warnings := configWarnings(cfg)
	if validateErr := cfg.Validate(); validateErr != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "config_invalid", fail(exitConfig, "%v", validateErr), warnings)
	}
	if *jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "config validate",
			Results:  []any{map[string]any{"path": path, "valid": true, "projects": len(cfg.Workspaces)}},
			Summary:  map[string]any{"valid": true, "projects": len(cfg.Workspaces)},
			Warnings: warnings, Errors: []jsonCommandError{},
		})
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	fmt.Printf("ok: %s is valid (%d workspace(s))\n", path, len(cfg.Workspaces))
	return nil
}

func runProjectList(args []string) error {
	fs := flag.NewFlagSet("project list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := fs.Bool("json", false, "write the versioned JSON envelope")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return jsonCommandFailure(*jsonOutput, "project list", "invalid_invocation", err, nil)
	}
	cfg, loadErr := config.Load(path)
	if loadErr != nil {
		return jsonCommandFailure(*jsonOutput, "project list", "config_unreadable", fail(exitConfig, "%v", loadErr), nil)
	}
	warnings := configWarnings(cfg)
	if validateErr := cfg.Validate(); validateErr != nil {
		return jsonCommandFailure(*jsonOutput, "project list", "config_invalid", fail(exitConfig, "%v", validateErr), warnings)
	}
	results := make([]projectListResult, 0, len(cfg.Workspaces))
	for _, workspace := range cfg.Workspaces {
		canonical, canonicalErr := filepath.EvalSymlinks(workspace.Path)
		if canonicalErr != nil {
			return jsonCommandFailure(*jsonOutput, "project list", "config_invalid", fail(exitConfig, "canonicalize workspace %s: %v", workspace.Path, canonicalErr), warnings)
		}
		canonical, canonicalErr = filepath.Abs(canonical)
		if canonicalErr != nil {
			return jsonCommandFailure(*jsonOutput, "project list", "config_invalid", fail(exitConfig, "canonicalize workspace %s: %v", workspace.Path, canonicalErr), warnings)
		}
		results = append(results, projectListResult{Name: config.WorkspaceName(workspace), Path: canonical})
	}
	if *jsonOutput {
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "project list", Results: results,
			Summary: map[string]int{"projects": len(results)}, Warnings: warnings, Errors: []jsonCommandError{},
		})
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	if len(results) == 0 {
		fmt.Println("No projects configured.")
		return nil
	}
	for _, result := range results {
		fmt.Printf("%s\t%s\n", result.Name, result.Path)
	}
	return nil
}

func runProjectAdd(args []string) error {
	fs := flag.NewFlagSet("project add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "persistent project name")
	stack := fs.String("stack", "", "selected stack: python, node, or docker")
	manager := fs.String("package-manager", "", "selected package manager for python or node")
	composeFile := fs.String("compose-file", "", "project-relative Compose file for the test profile")
	service := fs.String("test-service", "", "Compose test service")
	branch := fs.String("branch", "", "protected branch")
	remote := fs.String("remote", "", "Git remote")
	yes := fs.Bool("yes", false, "confirm the displayed config diff")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting")
	var allowPaths, dockerFiles, runtimeImages repeatedFlag
	fs.Var(&allowPaths, "allow-path", "allowed changed path (repeatable)")
	fs.Var(&dockerFiles, "docker-file", "project-relative Dockerfile for docker stack (repeatable)")
	fs.Var(&runtimeImages, "runtime-image", "immutable runtime image digest for docker stack (repeatable)")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	positional := fs.Args()
	if len(positional) < 1 || len(positional) > 2 {
		return fail(exitConfig, "usage: vuelta project add [options] <path> [config-path]")
	}
	configFile, err := configPath(positional[1:])
	if err != nil {
		return err
	}
	discovery, err := configinit.Detect(positional[0])
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	input := configinit.Input{
		Name: *name, Stack: *stack, PackageManager: *manager, ComposeFile: *composeFile,
		TestService: *service, Branch: *branch, Remote: *remote,
		AllowedPaths: allowPaths, DockerFiles: dockerFiles, RuntimeImages: runtimeImages,
	}
	interactive := !*nonInteractive && configinit.IsTerminal(os.Stdin)
	var workspace config.Workspace
	for {
		workspace, err = discovery.BuildWorkspace(input)
		if err == nil {
			break
		}
		var missing *configinit.MissingValueError
		if !interactive || !errors.As(err, &missing) {
			return fail(exitConfig, "%v", err)
		}
		value, promptErr := promptChoice(missing.Flag, missing.Options)
		if promptErr != nil {
			return fail(exitConfig, "%v", promptErr)
		}
		setProjectInput(&input, missing.Flag, value)
	}
	plan, err := configinit.PlanWorkspaceAdd(configFile, workspace)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if !plan.Changed {
		fmt.Printf("project %s is already configured at %s\n", workspace.Name, workspace.Path)
		return nil
	}
	fmt.Fprint(os.Stderr, plan.Diff(configFile))
	if !*yes {
		if !interactive {
			return fail(exitConfig, "project add requires confirmation; rerun with --yes")
		}
		confirmed, confirmErr := promptConfirmation("Apply this project config change?")
		if confirmErr != nil {
			return fail(exitConfig, "%v", confirmErr)
		}
		if !confirmed {
			return fail(exitConfig, "project addition cancelled")
		}
	}
	if err := plan.Apply(configFile); err != nil {
		return fail(exitConfig, "%v", err)
	}
	fmt.Printf("added project %s: %s\n", workspace.Name, workspace.Path)
	return nil
}

func setProjectInput(input *configinit.Input, flagName, value string) {
	switch flagName {
	case "--stack":
		input.Stack = value
	case "--package-manager":
		input.PackageManager = value
	case "--compose-file":
		input.ComposeFile = value
	case "--test-service":
		input.TestService = value
	case "--branch":
		input.Branch = value
	case "--remote":
		input.Remote = value
	case "--allow-path":
		input.AllowedPaths = []string{value}
	}
}

func configWarnings(cfg *config.Config) []string {
	warnings := make([]string, 0)
	if warning, ok := cfg.PermissionWarning(); ok {
		warnings = append(warnings, strings.TrimPrefix(warning, "warning: "))
	}
	warnings = append(warnings, cfg.WorkspaceWarnings()...)
	return warnings
}

func jsonCommandFailure(enabled bool, command, code string, commandErr error, warnings []string) error {
	if !enabled {
		return commandErr
	}
	envelopeErr := writeJSONEnvelope(jsonCommandEnvelope{
		Format: 1, Command: command, Results: []any{}, Summary: map[string]any{},
		Warnings: nonNilStrings(warnings), Errors: []jsonCommandError{{Code: code, Message: commandErr.Error()}},
	})
	if envelopeErr != nil {
		return envelopeErr
	}
	return commandErr
}

func writeJSONEnvelope(envelope jsonCommandEnvelope) error {
	if envelope.Warnings == nil {
		envelope.Warnings = []string{}
	}
	if envelope.Errors == nil {
		envelope.Errors = []jsonCommandError{}
	}
	if err := json.NewEncoder(os.Stdout).Encode(envelope); err != nil {
		return fail(exitFailure, "write JSON output: %v", err)
	}
	return nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
