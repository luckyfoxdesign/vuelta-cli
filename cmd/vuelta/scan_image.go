package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

func runBuiltImageScan(args []string) error {
	flags := flag.NewFlagSet("scan image", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var repositories repeatedFlag
	flags.Var(&repositories, "allow-repository", "")
	timeout := flags.Duration("timeout", defaultProjectScanTimeout, "")
	failOn := flags.String("fail-on", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 || *timeout <= 0 || *timeout > maxProjectScanTimeout || (*failOn != "" && *failOn != "vulnerabilities") {
		return builtImageCommandFailure(exitConfig, "invalid_invocation")
	}
	input, err := vulnscan.DecodeBuiltImageInput(os.Stdin)
	if err != nil {
		return builtImageCommandFailure(exitConfig, "invalid_image_input")
	}
	if err := vulnscan.ValidateBuiltImageInput(input, repositories, time.Now()); err != nil {
		return builtImageCommandFailure(exitConfig, "invalid_image_input")
	}
	path, err := configPath(flags.Args())
	if err != nil {
		return builtImageCommandFailure(exitConfig, "configuration_unavailable")
	}
	// No onboarding, migration, selected-project discovery or ambient Docker
	// configuration: the explicit/default machine config supplies trust only.
	cfg, err := config.Load(path)
	if err != nil {
		return builtImageCommandFailure(exitConfig, "configuration_unavailable")
	}
	if err := cfg.Validate(); err != nil {
		return builtImageCommandFailure(exitConfig, "invalid_configuration")
	}
	if cfg.VulnScan.ImageScan.Image == "" {
		cfg.VulnScan.ImageScan.Image = configinit.NewConfig().VulnScan.Image
	}
	if err := configureDeveloperDocker(*cfg); err != nil {
		return builtImageCommandFailure(exitEnv, "docker_unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	report, scanErr := executeBuiltImageScan(ctx, input, repositories, *cfg, path)
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return fail(exitFailure, "write image scan JSON")
	}
	if scanErr != nil {
		return fail(exitPartial, "image scan failed; see JSON status and error")
	}
	if *failOn == "vulnerabilities" && len(report.Findings) > 0 {
		return fail(exitFindings, "image vulnerabilities found")
	}
	return nil
}

func builtImageCommandFailure(code int, reason string) error {
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Error         string `json:"error"`
	}{1, "failed", reason}); err != nil {
		return fail(exitFailure, "write image scan JSON")
	}
	return fail(code, "%s", reason)
}

func executeBuiltImageScan(ctx context.Context, input vulnscan.BuiltImageInput, repositories []string, cfg config.Config, path string) (report vulnscan.BuiltImageReport, err error) {
	report = vulnscan.BuiltImageReport{SchemaVersion: 1, Artifact: input.Artifact, Status: "failed", ProductionComparison: "not_provided", Coverage: vulnscan.ImageCoverage{OS: "unknown", Libraries: "unknown"}, Findings: []vulnscan.JSONFinding{}}
	invocation, err := runlease.NewID()
	if err != nil {
		report.Error = "cleanup_setup_failed"
		return report, err
	}
	ctx, err = runlease.WithInvocation(ctx, invocation)
	if err != nil {
		report.Error = "cleanup_setup_failed"
		return report, err
	}
	executable, err := os.Executable()
	if err != nil {
		report.Error = "cleanup_setup_failed"
		return report, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		report.Error = "cleanup_setup_failed"
		return report, err
	}
	dockerPath, err := dockerexec.Default().Path()
	if err != nil {
		report.Error = "docker_unavailable"
		return report, err
	}
	socket, err := selectedDeveloperDockerSocket()
	if err != nil {
		report.Error = "docker_unavailable"
		return report, err
	}
	guardian, err := startScanCleanupGuardian(executable, path, dockerPath, invocation, socket)
	if err != nil {
		report.Error = "cleanup_setup_failed"
		return report, err
	}
	session := egress.NewSession(cfg.Update.Egress, dockerexec.Default())
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cleanupErr := session.Close(cleanupCtx)
		guardianErr := guardian.Finish(cleanupCtx, cleanupErr == nil && ctx.Err() == nil)
		if cleanupErr != nil || guardianErr != nil {
			report.Status, report.Error = "failed", "image_cleanup_failed"
			err = errors.Join(err, cleanupErr, guardianErr)
		}
	}()
	return (vulnscan.Scanner{}).ScanBuiltImage(egress.WithSession(ctx, session), input, repositories, cfg)
}
