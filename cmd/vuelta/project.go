package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
)

type jsonCommandError struct {
	Code             string   `json:"code"`
	Message          string   `json:"message"`
	Hint             string   `json:"hint,omitempty"`
	Stage            string   `json:"stage,omitempty"`
	Category         string   `json:"category,omitempty"`
	ExitCode         *int     `json:"exit_code,omitempty"`
	StderrTail       string   `json:"stderr_tail,omitempty"`
	RetryHistory     []string `json:"retry_history,omitempty"`
	CacheStatus      string   `json:"cache_status,omitempty"`
	DatabaseAgeHours *int     `json:"database_age_hours,omitempty"`
}

type jsonCommandEnvelope struct {
	Format   int                  `json:"format"`
	Command  string               `json:"command"`
	Results  any                  `json:"results"`
	Summary  any                  `json:"summary"`
	Warnings []string             `json:"warnings"`
	Errors   []jsonCommandError   `json:"errors"`
	Config   *scanConfigSelection `json:"config,omitempty"`
}

type projectListResult struct {
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	Verification    []string `json:"verification"`
	Toolchain       string   `json:"toolchain,omitempty"`
	ToolchainSource string   `json:"toolchain_source,omitempty"`
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
	cfg, loadErr := loadMachineConfig(path, !*jsonOutput && configinit.IsTerminal(os.Stdin))
	if loadErr != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "config_unreadable", fail(exitConfig, "%v", loadErr), nil)
	}
	warnings := configWarnings(cfg)
	if validateErr := cfg.Validate(); validateErr != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "config_invalid", fail(exitConfig, "%v", validateErr), warnings)
	}
	if validateErr := validateVerificationPolicies(*cfg); validateErr != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "config_invalid", fail(exitConfig, "%v", validateErr), warnings)
	}
	if validateErr := validateToolchainPolicies(*cfg); validateErr != nil {
		return jsonCommandFailure(*jsonOutput, "config validate", "config_invalid", fail(exitConfig, "%v", validateErr), warnings)
	}
	if *jsonOutput {
		plans := make([]map[string]any, 0, len(cfg.Workspaces))
		for _, workspace := range cfg.Workspaces {
			profileID, source := resolvedToolchain(workspace, *cfg)
			plans = append(plans, map[string]any{"project": config.WorkspaceName(workspace), "verification": config.VerificationPlan(workspace), "toolchain": profileID, "toolchain_source": source})
		}
		return writeJSONEnvelope(jsonCommandEnvelope{
			Format: 1, Command: "config validate",
			Results: []any{map[string]any{
				"path": path, "valid": true, "projects": len(cfg.Workspaces), "verification_plans": plans,
				"next": displayCommand("scan", "--directory", ".", "--only", "packages", "--config", path),
			}},
			Summary:  map[string]any{"valid": true, "projects": len(cfg.Workspaces)},
			Warnings: warnings, Errors: []jsonCommandError{},
		})
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	fmt.Printf("ok: %s is valid (%d workspace(s))\n", path, len(cfg.Workspaces))
	for _, workspace := range cfg.Workspaces {
		for _, step := range config.VerificationPlan(workspace) {
			fmt.Printf("verification %s: %s\n", config.WorkspaceName(workspace), step)
		}
		if profileID, source := resolvedToolchain(workspace, *cfg); profileID != "" {
			fmt.Printf("toolchain %s: %s (source=%s)\n", config.WorkspaceName(workspace), profileID, source)
		}
	}
	fmt.Printf("Next: %s\n", displayCommand("scan", "--directory", ".", "--only", "packages", "--config", path))
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
	cfg, loadErr := loadMachineConfig(path, !*jsonOutput && configinit.IsTerminal(os.Stdin))
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
		toolchainID, toolchainSource := workspace.ToolchainProfile, ""
		if workspace.PackageManager != "" {
			selection, resolveErr := toolchain.Select(workspace, *cfg)
			if resolveErr != nil {
				return jsonCommandFailure(*jsonOutput, "project list", "config_invalid", fail(exitConfig, "%v", resolveErr), warnings)
			}
			toolchainID, toolchainSource = selection.Profile.ID, selection.Source
		}
		results = append(results, projectListResult{Name: config.WorkspaceName(workspace), Path: canonical, Verification: config.VerificationPlan(workspace), Toolchain: toolchainID, ToolchainSource: toolchainSource})
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
		for _, step := range result.Verification {
			fmt.Printf("  verification: %s\n", step)
		}
		if result.Toolchain != "" {
			fmt.Printf("  toolchain: %s (source=%s)\n", result.Toolchain, result.ToolchainSource)
		}
	}
	return nil
}

func runProjectAdd(args []string) error {
	fs := flag.NewFlagSet("project add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "persistent project name")
	stack := fs.String("stack", "", "selected stack: python, node, or docker")
	manager := fs.String("package-manager", "", "selected package manager or requirements scan profile")
	toolchainProfile := fs.String("toolchain-profile", "", "operator override profile ID (detected default when omitted)")
	platform := fs.String("platform", "", "scanner platform: linux/amd64 or linux/arm64")
	branch := fs.String("branch", "", "protected branch")
	remote := fs.String("remote", "", "Git remote")
	scanOnly := fs.Bool("scan-only", false, "register the project for read-only scans without update authority")
	yes := fs.Bool("yes", false, "confirm the displayed config diff")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting")
	var allowPaths, dockerFiles, runtimeImages, verificationNames repeatedFlag
	fs.Var(&allowPaths, "allow-path", "allowed changed path (repeatable)")
	fs.Var(&dockerFiles, "docker-file", "project-relative Dockerfile for docker stack (repeatable)")
	fs.Var(&runtimeImages, "runtime-image", "immutable runtime image digest for docker stack (repeatable)")
	fs.Var(&verificationNames, "verification", "declarative verification candidate (repeatable for a multi-step profile)")
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
		Name: *name, Stack: *stack, PackageManager: *manager, Branch: *branch, Remote: *remote,
		AllowedPaths: allowPaths, DockerFiles: dockerFiles, RuntimeImages: runtimeImages,
		VerificationNames: verificationNames, ScanOnly: *scanOnly,
	}
	interactive := !*nonInteractive && configinit.IsTerminal(os.Stdin)
	workspace, err := resolveAmbiguousWorkspace(discovery, input, interactive, promptChoice)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	workspace.ToolchainProfile = *toolchainProfile
	workspace.Platform = *platform
	configured, loadErr := loadMachineConfig(configFile, !*nonInteractive && configinit.IsTerminal(os.Stdin))
	if loadErr != nil {
		return fail(exitConfig, "%v", loadErr)
	}
	if validateErr := configured.Validate(); validateErr != nil {
		return fail(exitConfig, "%v", validateErr)
	}
	var selectedToolchain string
	if workspace.PackageManager != "" {
		selection, resolveErr := toolchain.Select(workspace, *configured)
		if resolveErr != nil {
			return fail(exitConfig, "%v", resolveErr)
		}
		profile, constraints := selection.Profile, selection.Constraints
		selectedToolchain = fmt.Sprintf("%s source=%s runtime=%s manager=%s@%s lock=%s platform=%s", profile.ID, selection.Source, profile.Runtime, profile.PackageManager, profile.PackageManagerVersion, constraints.LockFormat, profile.Platform)
	}
	plan, err := configinit.PlanWorkspaceAdd(configFile, workspace)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if !plan.Changed {
		fmt.Printf("project %s is already configured at %s\n", workspace.Name, workspace.Path)
		return nil
	}
	for _, step := range config.VerificationPlan(workspace) {
		fmt.Fprintf(os.Stderr, "verification plan: %s\n", step)
	}
	if selectedToolchain != "" {
		fmt.Fprintf(os.Stderr, "toolchain profile: %s\n", selectedToolchain)
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
	case "--verification":
		input.VerificationNames = append(input.VerificationNames, value)
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
	warnings = append(warnings, cfg.WorkspaceWarnings()...)
	return warnings
}

func validateVerificationPolicies(cfg config.Config) error {
	var errs []error
	for _, workspace := range cfg.Workspaces {
		if workspace.Verification.State != config.VerificationReady {
			continue
		}
		if err := testrunner.ValidateProfile(workspace.Path, workspace.Verification); err != nil {
			errs = append(errs, fmt.Errorf("project %q verification policy: %w", config.WorkspaceName(workspace), err))
		}
	}
	return errors.Join(errs...)
}

func validateToolchainPolicies(cfg config.Config) error {
	var errs []error
	for _, workspace := range cfg.Workspaces {
		if workspace.PackageManager == "" {
			continue
		}
		if _, err := toolchain.Select(workspace, cfg); err != nil {
			errs = append(errs, fmt.Errorf("project %q toolchain: %w", config.WorkspaceName(workspace), err))
		}
	}
	return errors.Join(errs...)
}

func resolvedToolchain(workspace config.Workspace, cfg config.Config) (string, string) {
	if workspace.PackageManager == "" {
		return workspace.ToolchainProfile, ""
	}
	selection, err := toolchain.Select(workspace, cfg)
	if err != nil {
		return "", ""
	}
	return selection.Profile.ID, selection.Source
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
