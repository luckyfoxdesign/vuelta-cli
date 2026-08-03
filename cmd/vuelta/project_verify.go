package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
)

// resolveVerifyDigest is overridden in tests so they never need a real
// Docker daemon or registry.
var resolveVerifyDigest updater.PlatformDigestResolver = updater.ResolveDigestForPlatformViaManifest

// runProjectVerifyInit generates and writes only compose.verify.yml. It never
// touches .vuelta.yaml or the machine config: promotion to a ready
// verification profile is a separate, explicit step (vuelta project verify
// approve).
func runProjectVerifyInit(args []string) error {
	fs := flag.NewFlagSet("project verify init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	directory := fs.String("directory", ".", "project root to generate compose.verify.yml for")
	scriptName := fs.String("script", "", "explicit package.json script name (overrides automatic detection)")
	refreshImage := fs.Bool("refresh-image", false, "refresh only the existing verification base image digest")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) > 1 {
		return fail(exitConfig, "usage: vuelta project verify init [--directory PATH] [--script NAME] [--refresh-image] [config-path]")
	}
	if *refreshImage && *scriptName != "" {
		return fail(exitConfig, "--refresh-image and --script are mutually exclusive")
	}
	configFile, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	projectRoot, rootErr := canonicalDirectory(*directory)
	if rootErr != nil {
		return fail(exitConfig, "%v", rootErr)
	}
	projectPath := filepath.Join(projectRoot, projectConfigName)
	project, projectErr := config.LoadProject(projectPath)
	if projectErr != nil {
		return fail(exitConfig, "load project policy: %v; run vuelta scan --directory %s first", projectErr, projectRoot)
	}
	cfg, _, err := mergeProjectWithMachinePath(project, projectPath, "reused", configFile)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	*directory = projectRoot
	if err := cfg.Validate(); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if err := configureDeveloperDocker(*cfg); err != nil {
		return fail(exitEnv, "%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if *refreshImage {
		result, err := configinit.RefreshVerifyComposeImage(ctx, *directory, resolveVerifyDigest)
		if err != nil {
			return fail(exitConfig, "%v", err)
		}
		if result.Changed {
			fmt.Printf("refreshed verification image in %s (%s -> %s)\n", result.Path, result.PreviousDigest, result.CurrentDigest)
		} else {
			fmt.Printf("verification image is current in %s (%s)\n", result.Path, result.CurrentDigest)
		}
		return nil
	}
	path, selected, err := configinit.WriteVerifyCompose(ctx, *directory, *scriptName, resolveVerifyDigest)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	fmt.Printf("wrote %s (script=%s)\n", path, selected)
	fmt.Printf("Next: %s\n", displayCommand("project", "verify", "approve"))
	return nil
}

// runProjectVerifyApprove promotes only the project-local verification block
// after showing the exact resolved steps and byte-preserving config diff.
func runProjectVerifyApprove(args []string) error {
	fs := flag.NewFlagSet("project verify approve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	directory := fs.String("directory", ".", "project root containing .vuelta.yaml")
	yes := fs.Bool("yes", false, "confirm the displayed verification config diff")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting for confirmation")
	var verificationNames repeatedFlag
	fs.Var(&verificationNames, "verification", "declarative verification candidate (repeatable for a multi-step profile)")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) != 0 {
		return fail(exitConfig, "usage: vuelta project verify approve [--directory PATH] [--verification NAME] [--yes]")
	}

	projectPath := filepath.Join(*directory, projectConfigName)
	project, err := config.LoadProjectForVerificationApproval(projectPath)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	workspace, err := project.ResolvedWorkspace(projectPath)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	discovery, err := configinit.Detect(workspace.Path)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	profile, err := discovery.BuildReadyVerification(workspace, verificationNames)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	plan, err := configinit.PlanProjectVerificationUpdate(projectPath, profile)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	workspace.Verification = profile
	for _, step := range config.VerificationPlan(workspace) {
		fmt.Fprintf(os.Stderr, "verification plan: %s\n", step)
	}
	fmt.Fprint(os.Stderr, plan.Diff(projectPath))
	if !*yes {
		interactive := !*nonInteractive && configinit.IsTerminal(os.Stdin)
		if !interactive {
			return fail(exitConfig, "project verification approval requires confirmation; rerun with --yes")
		}
		confirmed, confirmErr := promptConfirmation("Apply this project verification profile?")
		if confirmErr != nil {
			return fail(exitConfig, "%v", confirmErr)
		}
		if !confirmed {
			return fail(exitConfig, "project verification approval cancelled")
		}
	}
	if err := plan.Apply(projectPath); err != nil {
		return fail(exitConfig, "%v", err)
	}
	fmt.Printf("approved verification profile: %s\n", projectPath)
	return nil
}
