package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
)

// resolveVerifyDigest is overridden in tests so they never need a real
// Docker daemon or registry.
var resolveVerifyDigest updater.DigestResolver = updater.ResolveDigestViaManifest

// runProjectVerifyInit generates and writes only compose.verify.yml. It never
// touches .vuelta.yaml or the machine config: promotion to a ready
// verification profile is a separate, explicit step (vuelta project verify
// approve).
func runProjectVerifyInit(args []string) error {
	fs := flag.NewFlagSet("project verify init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	directory := fs.String("directory", ".", "project root to generate compose.verify.yml for")
	scriptName := fs.String("script", "", "explicit package.json script name (overrides automatic detection)")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if len(fs.Args()) != 0 {
		return fail(exitConfig, "usage: vuelta project verify init [--directory PATH] [--script NAME]")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	path, selected, err := configinit.WriteVerifyCompose(ctx, *directory, *scriptName, resolveVerifyDigest)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	fmt.Printf("wrote %s (script=%s)\n", path, selected)
	fmt.Printf("Next: %s\n", displayCommand("project", "verify", "approve"))
	return nil
}
