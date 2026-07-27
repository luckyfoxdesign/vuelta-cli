package corpus

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
)

const productionBuildTimeout = 10 * time.Minute

// BuildProductionVuelta compiles the production CLI inside the corpus
// container. It is never called by offline tests.
func BuildProductionVuelta(ctx context.Context, sourceRoot, target, stateDir string) error {
	if !filepath.IsAbs(sourceRoot) || !filepath.IsAbs(target) || !filepath.IsAbs(stateDir) {
		return errors.New("production build paths must be absolute")
	}
	info, err := os.Stat(sourceRoot)
	if err != nil || !info.IsDir() {
		return errors.New("production Vuelta source root is unavailable")
	}
	const goExecutable = "/usr/local/go/bin/go"
	if info, err := os.Stat(goExecutable); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("container Go executable is unavailable")
	}
	buildCtx, cancel := context.WithTimeout(ctx, productionBuildTimeout)
	defer cancel()
	output := capio.NewTail(64 << 10)
	command := exec.CommandContext(buildCtx, goExecutable, "build", "-trimpath", "-o", target, "./cmd/vuelta")
	command.Dir = sourceRoot
	command.Env = []string{
		"CGO_ENABLED=0",
		"GOCACHE=" + filepath.Join(stateDir, "go-build"),
		"GOMODCACHE=/go/pkg/mod",
		"HOME=" + stateDir,
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/local/go/bin:/usr/bin:/bin",
		"TMPDIR=" + stateDir,
	}
	command.Stdout = output
	command.Stderr = output
	command.WaitDelay = 10 * time.Second
	if err := command.Run(); err != nil {
		if errors.Is(buildCtx.Err(), context.DeadlineExceeded) {
			return errors.New("production Vuelta build timed out")
		}
		return fmt.Errorf("build production Vuelta CLI: %s", SanitizeMessage(output.String()))
	}
	return nil
}

// SourceRevision returns the exact app commit without inspecting file content.
func SourceRevision(ctx context.Context, sourceRoot string) string {
	output, err := gitexec.Output(ctx, sourceRoot, "rev-parse", "HEAD")
	if err != nil {
		return "unknown"
	}
	revision := SanitizeMessage(string(output))
	if !fullCommitPattern.MatchString(revision) {
		return "unknown"
	}
	return revision
}
