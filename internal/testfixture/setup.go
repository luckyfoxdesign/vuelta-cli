package testfixture

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SetupProject copies a named fixture into destination and initializes a new
// standalone Git repository there. Fixtures intentionally contain no nested
// .git directory, so every caller gets an isolated repository and commit.
func SetupProject(ctx context.Context, root, name, destination string) error {
	if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") {
		return fmt.Errorf("invalid fixture name %q", name)
	}
	source := filepath.Join(root, name)
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat fixture %q: %w", name, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("fixture %q is not a directory", name)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return fmt.Errorf("create fixture destination: %w", err)
	}
	if err := copyTree(source, destination); err != nil {
		return fmt.Errorf("copy fixture %q: %w", name, err)
	}
	for _, args := range [][]string{
		{"init", "-q", "--initial-branch=main"},
		{"config", "user.email", "fixture@example.invalid"},
		{"config", "user.name", "Vuelta fixture"},
		{"add", "-A"},
		{"commit", "-q", "-m", "fixture: " + name},
	} {
		if err := git(ctx, destination, args...); err != nil {
			return err
		}
	}
	return nil
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("fixture source must not contain symlinks")
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("fixture entry %q is not a regular file", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, entry.Type().Perm())
	})
}

func git(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
