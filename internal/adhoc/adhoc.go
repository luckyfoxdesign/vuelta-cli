// Package adhoc detects explicit unregistered project roots and prepares
// minimal private copies for container-only updates.
package adhoc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Project is one detected root-only manifest/lock-file pair.
type Project struct {
	Root        string
	Manager     string
	Manifest    string
	Lock        string
	ConfigFiles []string
}

// Detect resolves exactly one supported manifest/lock pair in path. It never
// searches parent directories or follows manifest and lock-file symlinks.
func Detect(path string) (Project, error) {
	root, err := filepath.Abs(path)
	if err != nil {
		return Project{}, fmt.Errorf("resolve adhoc project path: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Project{}, fmt.Errorf("resolve canonical adhoc project path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return Project{}, fmt.Errorf("stat adhoc project path: %w", err)
	}
	if !info.IsDir() {
		return Project{}, errors.New("adhoc project path must be a directory")
	}

	type definition struct {
		manager, manifest, lock string
		configs                 []string
	}
	definitions := []definition{
		{"npm", "package.json", "package-lock.json", []string{".npmrc"}},
		{"pnpm", "package.json", "pnpm-lock.yaml", []string{".npmrc", "pnpm-workspace.yaml"}},
		{"bun", "package.json", "bun.lock", []string{".npmrc", "bunfig.toml"}},
		{"poetry", "pyproject.toml", "poetry.lock", []string{"poetry.toml"}},
		{"uv", "pyproject.toml", "uv.lock", []string{}},
		{"pip-tools", "requirements.in", "requirements.txt", []string{"pip.conf"}},
	}
	var matches []Project
	for _, definition := range definitions {
		if regularFile(root, definition.manifest) && regularFile(root, definition.lock) {
			matches = append(matches, Project{
				Root: root, Manager: definition.manager, Manifest: definition.manifest,
				Lock: definition.lock, ConfigFiles: definition.configs,
			})
		}
	}
	if len(matches) == 0 {
		return Project{}, errors.New("adhoc project needs exactly one supported regular manifest/lock pair at its root")
	}
	if len(matches) != 1 {
		return Project{}, errors.New("adhoc project has multiple supported manifest/lock pairs; select a project with one pair")
	}
	return matches[0], nil
}

// InPrivateCopy runs operation against a minimal copy containing only the
// recognized dependency files and explicitly approved manager configuration.
// Only manifest and lock-file changes can be copied back to the host target.
func InPrivateCopy(path string, allowProjectConfig, apply bool, operation func(Project) error) ([]string, error) {
	project, err := Detect(path)
	if err != nil {
		return nil, err
	}
	if err := rejectProjectConfig(project, allowProjectConfig); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vuelta-adhoc-update-")
	if err != nil {
		return nil, fmt.Errorf("create private update copy: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict private update copy: %w", err)
	}
	files := []string{project.Manifest, project.Lock}
	if allowProjectConfig {
		for _, name := range project.ConfigFiles {
			if regularFile(project.Root, name) {
				files = append(files, name)
			}
		}
	}
	for _, name := range files {
		if err := copyRegularFile(project.Root, dir, name); err != nil {
			return nil, err
		}
	}
	copyProject := project
	copyProject.Root = dir
	before, err := privateProjectState(copyProject)
	if err != nil {
		return nil, err
	}
	if err := operation(copyProject); err != nil {
		return nil, err
	}
	after, err := privateProjectState(copyProject)
	if err != nil {
		return nil, err
	}
	if err := before.onlyAllowedChanges(after, copyProject); err != nil {
		return nil, fmt.Errorf("private update copy security check: %w", err)
	}
	changed := changedDependencyFiles(before, after, copyProject)
	if apply && len(changed) > 0 {
		if err := copyBackAtomically(project, copyProject, before, changed); err != nil {
			return nil, err
		}
	}
	return changed, nil
}

func regularFile(root, name string) bool {
	info, err := os.Lstat(filepath.Join(root, name))
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func rejectProjectConfig(project Project, allowed bool) error {
	if allowed {
		return nil
	}
	for _, name := range project.ConfigFiles {
		if _, err := os.Lstat(filepath.Join(project.Root, name)); err == nil {
			return fmt.Errorf("adhoc %s package-manager config is present; pass --allow-project-config only after reviewing registry, proxy, script-shell, and plugin settings", project.Manager)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat adhoc %s package-manager config: %w", project.Manager, err)
		}
	}
	return nil
}

func copyRegularFile(sourceRoot, destinationRoot, name string) error {
	info, err := os.Lstat(filepath.Join(sourceRoot, name))
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("copy dependency input %s: not a regular file", name)
	}
	data, err := os.ReadFile(filepath.Join(sourceRoot, name))
	if err != nil {
		return fmt.Errorf("read dependency input %s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(destinationRoot, name), data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write private dependency input %s: %w", name, err)
	}
	return nil
}

func changedDependencyFiles(before, after state, project Project) []string {
	var changed []string
	for _, name := range []string{project.Manifest, project.Lock} {
		if before[name] != after[name] {
			changed = append(changed, name)
		}
	}
	return changed
}

func copyBackAtomically(host, private Project, expected state, changed []string) error {
	hostState, err := projectState(host)
	if err != nil {
		return fmt.Errorf("revalidate host dependency inputs: %w", err)
	}
	for _, name := range []string{host.Manifest, host.Lock} {
		if hostState[name].digest != expected[name].digest || hostState[name].mode.Perm() != expected[name].mode.Perm() {
			return fmt.Errorf("host dependency input %s changed during private update", name)
		}
	}
	original := make(map[string][]byte, len(changed))
	modes := make(map[string]fs.FileMode, len(changed))
	for _, name := range changed {
		info, err := os.Lstat(filepath.Join(host.Root, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("copy back %s: host input is no longer a regular file", name)
		}
		data, err := os.ReadFile(filepath.Join(host.Root, name))
		if err != nil {
			return fmt.Errorf("read host input %s before copy back: %w", name, err)
		}
		original[name], modes[name] = data, info.Mode().Perm()
	}
	var replaced []string
	for _, name := range changed {
		data, err := os.ReadFile(filepath.Join(private.Root, name))
		if err == nil {
			err = atomicWrite(filepath.Join(host.Root, name), data, modes[name])
		}
		if err != nil {
			var restoreErrs []error
			for _, restore := range replaced {
				if restoreErr := atomicWrite(filepath.Join(host.Root, restore), original[restore], modes[restore]); restoreErr != nil {
					restoreErrs = append(restoreErrs, fmt.Errorf("restore %s: %w", restore, restoreErr))
				}
			}
			if restoreErr := errors.Join(restoreErrs...); restoreErr != nil {
				return fmt.Errorf("atomically copy back %s: %w; rollback incomplete: %v", name, err, restoreErr)
			}
			return fmt.Errorf("atomically copy back %s: %w", name, err)
		}
		replaced = append(replaced, name)
	}
	return nil
}

func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vuelta-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type fileState struct {
	mode    fs.FileMode
	size    int64
	modTime time.Time
	digest  string
}

type state map[string]fileState

func privateProjectState(project Project) (state, error) {
	result, err := projectState(project)
	if err != nil {
		return nil, err
	}
	for name, item := range result {
		if !item.mode.IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(project.Root, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		item.digest = fmt.Sprintf("%x", sum)
		result[name] = item
	}
	return result, nil
}

func projectState(project Project) (state, error) {
	entries, err := os.ReadDir(project.Root)
	if err != nil {
		return nil, err
	}
	result := make(state, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".env") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		item := fileState{mode: info.Mode(), size: info.Size(), modTime: info.ModTime()}
		if info.Mode().IsRegular() && (name == project.Manifest || name == project.Lock) {
			data, err := os.ReadFile(filepath.Join(project.Root, name))
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(data)
			item.digest = fmt.Sprintf("%x", sum)
		}
		result[name] = item
	}
	return result, nil
}

func (before state) onlyAllowedChanges(after state, project Project) error {
	allowed := map[string]bool{project.Manifest: true, project.Lock: true}
	for name, old := range before {
		current, ok := after[name]
		if !ok {
			if !allowed[name] {
				return fmt.Errorf("container package manager removed unallowlisted path %s", name)
			}
			continue
		}
		if old != current && !allowed[name] {
			return fmt.Errorf("container package manager changed unallowlisted path %s", name)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok && !allowed[name] {
			return fmt.Errorf("container package manager created unallowlisted path %s", name)
		}
	}
	if _, ok := after[project.Manifest]; !ok {
		return fmt.Errorf("container package manager removed manifest %s", project.Manifest)
	}
	if _, ok := after[project.Lock]; !ok {
		return fmt.Errorf("container package manager removed lock file %s", project.Lock)
	}
	return nil
}
