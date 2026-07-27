package ecosystems

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

const (
	npmManifest       = "package.json"
	npmPackageLock    = "package-lock.json"
	npmShrinkwrapLock = "npm-shrinkwrap.json"
)

type npmProject struct {
	detected bool
	lockFile string
}

func (a npmAdapter) Detect(root string) (bool, error) {
	project, err := inspectNPMProject(root)
	return project.detected, err
}

func (a npmAdapter) PackageInputForRoot(root string, allowManagerConfig bool) (ecosystem.InputContract, error) {
	return a.inputForRoot(root, allowManagerConfig, ecosystem.InputStagePackageCandidates)
}

func (a npmAdapter) DependencyInputForRoot(root string) (ecosystem.InputContract, error) {
	return a.inputForRoot(root, false, ecosystem.InputStageDependencyCVE)
}

func (a npmAdapter) inputForRoot(root string, allowManagerConfig bool, stage ecosystem.InputStage) (ecosystem.InputContract, error) {
	project, err := inspectNPMProject(root)
	if err != nil {
		return ecosystem.InputContract{}, err
	}
	if !project.detected {
		return ecosystem.InputContract{}, errors.New("selected root is not an npm project")
	}
	files := []ecosystem.InputFile{{
		Path: npmManifest, Category: ecosystem.InputCategoryManifest,
	}}
	if project.lockFile != "" {
		files = append(files, ecosystem.InputFile{
			Path: project.lockFile, Category: ecosystem.InputCategoryLock,
		})
	}
	if allowManagerConfig {
		files = append(files, ecosystem.InputFile{
			Path: ".npmrc", Category: ecosystem.InputCategoryManagerConfig,
			Optional: true, ReviewedManagerConfig: true,
		})
	}
	return ecosystem.InputContract{Stage: stage, Files: files}, nil
}

func inspectNPMProject(root string) (npmProject, error) {
	if root == "" {
		return npmProject{}, errors.New("npm project root is required")
	}
	present, err := regularRootEntry(root, npmManifest)
	if err != nil || !present {
		return npmProject{}, err
	}
	data, err := ecosystem.ReadRootFile(root, npmManifest, ecosystem.DefaultManifestLimit)
	if err != nil {
		return npmProject{}, err
	}
	var manifest struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return npmProject{}, fmt.Errorf("parse package.json project metadata: %w", err)
	}
	if family := packageManagerFamily(manifest.PackageManager); family != "" && family != "npm" {
		return npmProject{}, nil
	}

	var locks []string
	for _, name := range []string{npmPackageLock, npmShrinkwrapLock} {
		present, err := regularRootEntry(root, name)
		if err != nil {
			return npmProject{}, err
		}
		if present {
			locks = append(locks, name)
		}
	}
	if len(locks) > 1 {
		return npmProject{}, errors.New("npm project has both package-lock.json and npm-shrinkwrap.json; keep exactly one supported lockfile")
	}
	if len(locks) == 0 {
		for _, competing := range []string{"pnpm-lock.yaml", "bun.lock"} {
			present, err := regularRootEntry(root, competing)
			if err != nil {
				return npmProject{}, err
			}
			if present {
				return npmProject{}, nil
			}
		}
		return npmProject{detected: true}, nil
	}
	return npmProject{detected: true, lockFile: locks[0]}, nil
}

func regularRootEntry(root, name string) (bool, error) {
	info, err := os.Lstat(filepath.Join(root, name))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("inspect npm project metadata %s: %w", name, err)
	case !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0:
		return false, fmt.Errorf("npm project metadata %s must be a regular file", name)
	default:
		return true, nil
	}
}

func packageManagerFamily(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "@") {
		if index := strings.LastIndex(value, "@"); index > 0 {
			return value[:index]
		}
		return value
	}
	family, _, _ := strings.Cut(value, "@")
	return family
}

func npmMutationLock(root string) (string, error) {
	if root == "" {
		return npmPackageLock, nil
	}
	project, err := inspectNPMProject(root)
	if err != nil {
		return "", err
	}
	if !project.detected || project.lockFile == "" {
		return "", errors.New("npm mutation requires exactly one supported lockfile")
	}
	return project.lockFile, nil
}
