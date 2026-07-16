// Command vuelta-scheduler is the external multi-project orchestration helper.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/luckyfoxdesign/vuelta/internal/scheduler"
)

func main() {
	var options scheduler.Options
	vueltaPath := flag.String("vuelta", "/usr/local/bin/vuelta", "path to the vuelta binary")
	flag.StringVar(&options.ConfigPath, "config", "", "alternate vuelta config.yaml")
	flag.StringVar(&options.FailurePolicy, "failure-policy", scheduler.FailureContinue, "continue or stop after an independent project failure")
	flag.StringVar(&options.FindingsPolicy, "findings-policy", scheduler.FindingsReport, "report or fail when vulnerabilities are found")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "vuelta-scheduler: positional arguments are not accepted")
		os.Exit(scheduler.ExitFailure)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, exitCode := scheduler.Run(ctx, scheduler.ExecRunner{Path: *vueltaPath, Stderr: os.Stderr}, options)
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "vuelta-scheduler: write JSON report:", err)
		exitCode = scheduler.ExitFailure
	}
	if exitCode != scheduler.ExitOK {
		os.Exit(exitCode)
	}
}
