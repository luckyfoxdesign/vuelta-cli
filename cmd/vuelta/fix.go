package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/remediation"
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
)

func runFix(args []string) (runErr error) {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	var options scanOptions
	var repair remediation.Options
	verbose := fs.Bool("verbose", false, "show bounded repair diagnostics")
	fs.StringVar(&options.directory, "directory", "", "project directory")
	fs.StringVar(&options.stack, "stack", "", "detected stack")
	fs.BoolVar(&options.jsonOutput, "json", false, "structured JSON output")
	fs.StringVar(&repair.MinSeverity, "min-severity", "", "minimum severity")
	fs.Func("finding", "finding ID (repeatable)", func(id string) error {
		if id == "" {
			return errors.New("finding ID is required")
		}
		repair.FindingIDs = append(repair.FindingIDs, id)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if *verbose {
		repair.Diagnostic = func(err error) {
			fmt.Fprintln(os.Stderr, safeerr.Excerpt([]byte(err.Error()), 2048))
		}
	}
	if _, err := remediation.Plan(nil, nil, repair); err != nil {
		return fail(exitConfig, "%v", err)
	}
	options.repair = true
	options.explicitConfig = fs.NArg() == 1
	if options.directory == "" {
		options.directory = "."
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	cfg, selection, err := selectReadOnlyScanConfiguration(options, path)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	targets, err := resolveScanTargets(*cfg, options, currentDirectory)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	targets = prepareTargets(targets, options.stack, true)
	if len(targets) != 1 {
		return fail(exitConfig, "fix requires exactly one project")
	}
	target := targets[0]
	if target.err != nil {
		return fail(exitConfig, "%v", target.err)
	}
	cfg.VulnScan.ImageScan.Enabled = true
	cfg.VulnScan.ImageScan.Tool = "trivy"
	if cfg.VulnScan.ImageScan.Image == "" {
		cfg.VulnScan.ImageScan.Image = configinit.NewConfig().VulnScan.Image
	}
	if err := configureDeveloperDocker(*cfg); err != nil {
		return fail(exitEnv, "%v", err)
	}
	docker := dockerexec.Default()
	dockerPath, err := docker.Path()
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	machine := selection.Path
	if selection.Scope == "project" {
		machine = selection.MachineConfig
	}
	machine, err = filepath.Abs(machine)
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	// Detected references already come from the tracked files. Keep explicit
	// project/machine runtime policy separate from those inferred references.
	if target.origin == "adhoc" || selection.Status == "ephemeral" {
		if _, statErr := os.Lstat(filepath.Join(target.path, projectConfigName)); errors.Is(statErr, os.ErrNotExist) && target.workspace.DockerImages != nil {
			images := *target.workspace.DockerImages
			images.RuntimeImages = nil
			target.workspace.DockerImages = &images
		}
	}
	invocation, err := runlease.NewID()
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	base, cancel := context.WithTimeout(signals, 20*time.Minute)
	defer cancel()
	ctx, err := runlease.WithInvocation(base, invocation)
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	socket, err := selectedDeveloperDockerSocket()
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	guardian, err := startScanCleanupGuardian(executable, machine, dockerPath, invocation, socket)
	if err != nil {
		return fail(exitEnv, "%v", err)
	}
	session := egress.NewSession(cfg.Update.Egress, docker)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		closeErr := session.Close(cleanup)
		guardErr := guardian.Finish(cleanup, closeErr == nil && ctx.Err() == nil)
		if runErr == nil && errors.Join(closeErr, guardErr) != nil {
			runErr = fail(exitPartial, "repair resource cleanup could not be confirmed")
		}
	}()
	result, err := (remediation.Engine{}).Run(egress.WithSession(ctx, session), *target.workspace, *cfg, repair)
	if options.jsonOutput {
		if writeErr := writeJSONEnvelope(jsonCommandEnvelope{Format: 1, Command: "fix", Results: []remediation.Result{result}}); writeErr != nil {
			return writeErr
		}
	} else {
		fmt.Printf("Fixed: %d, skipped: %d, changed files: %d\n", len(result.Fixed), len(result.Skipped), len(result.ChangedFiles))
		for _, item := range result.Skipped {
			fmt.Printf("%s: %s\n", item.Finding.ID, item.Reason)
		}
	}
	if signals.Err() != nil {
		return fail(exitInterrupted, "repair interrupted")
	}
	if err != nil {
		return fail(exitPartial, "%v", err)
	}
	return nil
}
