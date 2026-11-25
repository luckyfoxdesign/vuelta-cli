package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/runlease"
)

const cleanupGuardianCommand = "__vuelta-cleanup-guardian"

func runCleanupGuardian(args []string) error {
	flags := flag.NewFlagSet(cleanupGuardianCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "")
	dockerPath := flags.String("docker", "", "")
	socket := flags.String("socket", "", "")
	invocation := flags.String("invocation", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid cleanup guardian invocation")
	}
	if !filepath.IsAbs(*configPath) || !filepath.IsAbs(*dockerPath) || !filepath.IsAbs(*socket) || !runlease.ValidID(*invocation) {
		return errors.New("invalid cleanup guardian authority")
	}
	parentPipe := os.NewFile(uintptr(3), "vuelta-parent-lease")
	if parentPipe == nil {
		return errors.New("cleanup guardian parent lease is unavailable")
	}
	defer func() { _ = parentPipe.Close() }()
	signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	cleanup, err := runlease.WaitForParent(parentPipe)
	if err != nil || !cleanup {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return errors.New("load cleanup guardian configuration")
	}
	if err := cfg.Validate(); err != nil {
		return errors.New("validate cleanup guardian configuration")
	}
	if cfg.Docker == nil {
		return errors.New("cleanup guardian Docker authority is unavailable")
	}
	endpoint, err := configuredCleanupEndpoint(*cfg, *socket)
	if err != nil {
		return errors.New("resolve cleanup guardian Docker authority")
	}
	executor := dockerexec.New(dockerexec.Options{
		Resolver: func(name string) (string, error) {
			if name != "docker" {
				return "", errors.New("unexpected cleanup executable")
			}
			return *dockerPath, nil
		},
		Endpoint: endpoint,
	})
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return runlease.Cleanup(cleanupCtx, executor, *invocation)
}
