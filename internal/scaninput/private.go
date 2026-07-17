package scaninput

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// PrivateContext is used only by an explicit same-user host scanner or a test
// seam. Container scans consume Bundle.Archive directly and never call this.
type PrivateContext struct {
	Dir  string
	once sync.Once
	err  error
}

// MaterializePrivate writes validated inputs under a private 0700 directory
// with 0600 files. Partial contexts are cleaned on error and cancellation.
func MaterializePrivate(ctx context.Context, bundle Bundle) (*PrivateContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vuelta-local-scan-")
	if err != nil {
		return nil, fmt.Errorf("create private local scan context: %w", err)
	}
	private := &PrivateContext{Dir: dir}
	fail := func(stageErr error) (*PrivateContext, error) {
		return nil, errors.Join(stageErr, private.Close())
	}
	paths := make([]string, 0, len(bundle.contents))
	for path := range bundle.contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		destination := filepath.Join(dir, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return fail(fmt.Errorf("create private local scan parent: %w", err))
		}
		if err := os.WriteFile(destination, bundle.contents[relative], 0o600); err != nil {
			return fail(fmt.Errorf("write private local scan input: %w", err))
		}
	}
	return private, nil
}

// Close truncates regular files before removing the private context.
func (c *PrivateContext) Close() error {
	if c == nil || c.Dir == "" {
		return nil
	}
	c.once.Do(func() {
		walkErr := filepath.Walk(c.Dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				return err
			}
			return file.Close()
		})
		removeErr := os.RemoveAll(c.Dir)
		if walkErr != nil || removeErr != nil {
			c.err = fmt.Errorf("remove private local scan context: %w", errors.Join(walkErr, removeErr))
		}
	})
	return c.err
}
