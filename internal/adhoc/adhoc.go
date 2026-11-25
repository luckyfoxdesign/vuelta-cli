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

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
)

// Project is one detected root-only manifest/lock-file pair.
type Project struct {
	Root        string
	Stack       string
	Manager     string
	Manifest    string
	Lock        string
	ConfigFiles []string
	Files       []string
}

// Detect resolves exactly one updateable manifest/lock pair in path. It never
// searches parent directories or follows manifest and lock-file symlinks.
func Detect(path string) (Project, error) {
	return detect(path, true)
}

// DetectScan resolves exactly one supported read-only project shape. Unlike
// Detect, it permits an adapter to expose a manifest without a mutation lock.
func DetectScan(path string) (Project, error) {
	return detect(path, false)
}

func detect(path string, requireLock bool) (Project, error) {
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

	adapters, err := catalog.Discover(root)
	if err != nil {
		return Project{}, fmt.Errorf("detect adhoc ecosystem: %w", err)
	}
	var matches []Project
	for _, adapter := range adapters {
		provider, ok := adapter.(ecosystem.InputProvider)
		if !ok {
			continue
		}
		contract := provider.PackageInput(true)
		if resolver, ok := adapter.(ecosystem.RootInputProvider); ok {
			contract, err = resolver.PackageInputForRoot(root, true)
			if err != nil {
				return Project{}, fmt.Errorf("resolve %s adhoc scan input: %w", adapter.Key().String(), err)
			}
		}
		project := Project{Root: root, Stack: adapter.Key().Stack, Manager: adapter.Key().PackageManager}
		requiredPresent := true
		for _, file := range contract.Files {
			if !file.Optional && !regularFile(root, file.Path) {
				requiredPresent = false
			}
			switch file.Category {
			case ecosystem.InputCategoryManifest:
				project.Manifest = file.Path
			case ecosystem.InputCategoryLock:
				project.Lock = file.Path
			case ecosystem.InputCategoryManagerConfig:
				project.ConfigFiles = append(project.ConfigFiles, file.Path)
			}
		}
		if requiredPresent && project.Manifest != "" && (!requireLock || project.Lock != "") {
			matches = append(matches, project)
		}
	}
	if len(matches) == 0 {
		if !requireLock {
			return Project{}, errors.New("adhoc scan needs exactly one supported regular project manifest at its root")
		}
		return Project{}, errors.New("adhoc project needs exactly one supported regular manifest/lock pair at its root")
	}
	if len(matches) != 1 {
		if !requireLock {
			return Project{}, errors.New("adhoc scan has multiple supported project manifests; select the stack or package manager explicitly")
		}
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
	files := projectFiles(project)
	if allowProjectConfig {
		for _, name := range project.ConfigFiles {
			if regularFile(project.Root, name) {
				files = append(files, name)
			}
		}
	}
	return inPrivateProject(project, files, apply, operation)
}

// InPrivateFiles admits only literal, non-secret root files. It validates all
// changes and performs the same race-checked atomic copyback as package repair.
// apply is false for inspection and for candidate image scans.
func InPrivateFiles(root string, files []string, apply bool, operation func(string) error) ([]string, error) {
	if len(files) == 0 || len(files) > 64 {
		return nil, errors.New("private repair requires 1 to 64 explicit files")
	}
	seen := map[string]bool{}
	for _, name := range files {
		if name == "" || filepath.Base(name) != name || name == "." || strings.ContainsAny(name, `/\`) || ecosystem.IsSecretLikePath(name) || seen[name] {
			return nil, errors.New("invalid private repair file allowlist")
		}
		seen[name] = true
	}
	project := Project{Root: root, Files: append([]string(nil), files...)}
	return inPrivateProject(project, project.Files, apply, func(p Project) error { return operation(p.Root) })
}

func projectFiles(p Project) []string {
	if p.Files != nil {
		return append([]string(nil), p.Files...)
	}
	return []string{p.Manifest, p.Lock}
}

func inPrivateProject(project Project, files []string, apply bool, operation func(Project) error) ([]string, error) {
	dir, err := os.MkdirTemp("", "vuelta-adhoc-update-")
	if err != nil {
		return nil, fmt.Errorf("create private update copy: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict private update copy: %w", err)
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
	// Reject unexpected paths before reading their contents for a digest.
	// A manager-created credential file or symlink must never be opened.
	admitted := map[string]bool{}
	for _, name := range files {
		admitted[name] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !admitted[entry.Name()] || !entry.Type().IsRegular() {
			return nil, errors.New("private update copy security check: package manager created an unallowlisted path")
		}
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
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 16<<20 {
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
	for _, name := range projectFiles(project) {
		// Package managers can rewrite identical bytes (or core can restore a
		// temporary manifest). An mtime change alone must not copy a file back.
		if before[name].digest != after[name].digest || before[name].mode != after[name].mode {
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
	for _, name := range projectFiles(host) {
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
		allowed := false
		for _, file := range projectFiles(project) {
			allowed = allowed || file == name
		}
		if info.Mode().IsRegular() && allowed {
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
	allowed := map[string]bool{}
	for _, name := range projectFiles(project) {
		allowed[name] = true
	}
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
	for _, name := range projectFiles(project) {
		if item, ok := after[name]; !ok || !item.mode.IsRegular() {
			return fmt.Errorf("container package manager removed or replaced input %s", name)
		}
	}
	return nil
}
