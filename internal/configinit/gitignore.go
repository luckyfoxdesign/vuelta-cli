package configinit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

const (
	projectStateIgnoreRule = "/.vuelta/"
	maxGitignoreBytes      = 1 << 20
)

// PlanProjectGitignore adds only the exact anchored private-state rule while
// preserving existing bytes, line endings, comments, mode, and final-newline
// style.
func PlanProjectGitignore(root string) (EditPlan, error) {
	path := filepath.Join(root, ".gitignore")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return EditPlan{
			Updated: []byte(projectStateIgnoreRule + "\n"),
			Mode:    0o644,
			Changed: true, RepositoryFile: true,
		}, nil
	}
	if err != nil {
		return EditPlan{}, fmt.Errorf("inspect project .gitignore: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return EditPlan{}, errors.New("project .gitignore must be a regular non-symlink file")
	}
	if info.Size() > maxGitignoreBytes {
		return EditPlan{}, fmt.Errorf("project .gitignore exceeds %d bytes", maxGitignoreBytes)
	}
	original, err := config.ReadProjectFile(path)
	if err != nil {
		return EditPlan{}, fmt.Errorf("read project .gitignore: %w", err)
	}
	if hasExactIgnoreRule(original) {
		return EditPlan{
			Original: original, Updated: original, Mode: info.Mode().Perm(),
			Exists: true, Changed: false, RepositoryFile: true,
		}, nil
	}
	lineEnding := []byte("\n")
	if bytes.Contains(original, []byte("\r\n")) {
		lineEnding = []byte("\r\n")
	}
	updated := append([]byte(nil), original...)
	switch {
	case len(original) == 0:
		updated = append(updated, []byte(projectStateIgnoreRule)...)
	case bytes.HasSuffix(original, lineEnding):
		updated = append(updated, []byte(projectStateIgnoreRule)...)
		updated = append(updated, lineEnding...)
	default:
		updated = append(updated, lineEnding...)
		updated = append(updated, []byte(projectStateIgnoreRule)...)
	}
	return EditPlan{
		Original: original, Updated: updated, Mode: info.Mode().Perm(),
		Exists: true, Changed: true, RepositoryFile: true,
	}, nil
}

func hasExactIgnoreRule(data []byte) bool {
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, line := range strings.Split(normalized, "\n") {
		if line == projectStateIgnoreRule {
			return true
		}
	}
	return false
}

// ApplyProjectOnboarding publishes the ignore edit and optional new project
// policy as one recoverable transaction. If the second write fails, the first
// is restored and any rollback failure is reported explicitly.
func ApplyProjectOnboarding(projectPlan *EditPlan, projectPath string, ignorePlan EditPlan, ignorePath string) error {
	if err := ignorePlan.Apply(ignorePath); err != nil {
		rollbackErr := restoreEdit(ignorePlan, ignorePath)
		if rollbackErr != nil {
			return errors.Join(
				fmt.Errorf("update project .gitignore: %w", err),
				fmt.Errorf("restore project .gitignore after publish failure: %w", rollbackErr),
			)
		}
		return fmt.Errorf("update project .gitignore: %w", err)
	}
	if projectPlan == nil || !projectPlan.Changed {
		return nil
	}
	if err := projectPlan.Apply(projectPath); err != nil {
		projectRollbackErr := restoreEdit(*projectPlan, projectPath)
		ignoreRollbackErr := restoreEdit(ignorePlan, ignorePath)
		if projectRollbackErr != nil || ignoreRollbackErr != nil {
			return errors.Join(
				fmt.Errorf("write project policy: %w", err),
				wrapRollbackError("restore project policy after partial onboarding", projectRollbackErr),
				wrapRollbackError("restore project .gitignore after partial onboarding", ignoreRollbackErr),
			)
		}
		return fmt.Errorf("write project policy (project .gitignore restored): %w", err)
	}
	return nil
}

func restoreEdit(plan EditPlan, path string) error {
	if !plan.Changed {
		return nil
	}
	current, mode, exists, err := readEditSource(path, plan.RepositoryFile)
	if err != nil {
		return err
	}
	if !exists || mode != plan.Mode || !bytes.Equal(current, plan.Updated) {
		return nil
	}
	if !plan.Exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	return replaceAtomic(path, plan.Original, plan.Mode)
}

func wrapRollbackError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
