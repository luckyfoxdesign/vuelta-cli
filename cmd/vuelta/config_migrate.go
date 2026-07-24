package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

var confirmSchemaMigration = func() (bool, error) {
	return promptConfirmation("Upgrade this machine config now?")
}

func runConfigMigrate(args []string) error {
	fs := flag.NewFlagSet("config migrate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	yes := fs.Bool("yes", false, "confirm the reviewed schema migration")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting for confirmation")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	path, err := configPath(fs.Args())
	if err != nil {
		return err
	}
	plan, err := configinit.PlanSchemaMigration(path)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if !plan.Changed {
		fmt.Printf("machine config is already current: %s\n", path)
		return nil
	}
	writeSchemaMigrationReview(path, plan.Review)
	if !*yes {
		if *nonInteractive || !configinit.IsTerminal(os.Stdin) {
			return fail(exitConfig, "config migration requires confirmation; rerun with --yes")
		}
		confirmed, confirmErr := confirmSchemaMigration()
		if confirmErr != nil {
			return fail(exitConfig, "%v", confirmErr)
		}
		if !confirmed {
			return fail(exitConfig, "config migration cancelled")
		}
	}
	if err := plan.Apply(path); err != nil {
		return fail(exitConfig, "%v", err)
	}
	fmt.Printf("migrated machine config to schema %d: %s\n", config.CurrentSchemaVersion, path)
	return nil
}

func loadMachineConfig(path string, allowPrompt bool) (*config.Config, error) {
	loaded, err := config.Load(path)
	if err == nil {
		return loaded, nil
	}
	plan, planErr := configinit.PlanSchemaMigration(path)
	if planErr != nil || !plan.Changed {
		return nil, err
	}
	if !allowPrompt {
		return nil, fmt.Errorf("%w; reviewed migration available via `vuelta config migrate --config PATH`", err)
	}
	writeSchemaMigrationReview(path, plan.Review)
	confirmed, confirmErr := confirmSchemaMigration()
	if confirmErr != nil {
		return nil, confirmErr
	}
	if !confirmed {
		return nil, errors.New("config migration cancelled")
	}
	if err := plan.Apply(path); err != nil {
		return nil, fmt.Errorf("apply machine config migration: %w", err)
	}
	fmt.Printf("migrated machine config to schema %d: %s\n", config.CurrentSchemaVersion, path)
	return config.Load(path)
}

func ensureMachineConfigSchema(path string, allowPrompt bool) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect machine config: %w", err)
	}
	_, err = loadMachineConfig(path, allowPrompt)
	return err
}

func writeSchemaMigrationReview(path string, changes []string) {
	fmt.Fprintf(os.Stderr, "Machine config upgrade available:\n  path: %s\n", path)
	for _, change := range changes {
		fmt.Fprintf(os.Stderr, "  change: %s\n", change)
	}
	fmt.Fprintln(os.Stderr, "  all other settings: preserved")
}
