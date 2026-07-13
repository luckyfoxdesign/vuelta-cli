package pipeline

import (
	"context"

	"github.com/luckyfoxdesign/vuelta/internal/sandbox"
)

// BasicSandbox extracts only tracked regular files at baseSHA into a fresh
// 0700 directory. It rejects symlinked workspace paths and unsafe archive
// entries, so package-manager code never sees .git, ignored files, .env, or
// another host path. Container isolation is enforced by updater/testrunner.
type BasicSandbox struct{}

// Prepare implements Sandbox.
func (BasicSandbox) Prepare(ctx context.Context, repoPath, baseSHA string) (string, func() error, error) {
	return sandbox.Prepare(ctx, repoPath, baseSHA)
}
