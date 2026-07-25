package updater

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

var ncuVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func validateNCUVersion(version string) error {
	if !ncuVersionPattern.MatchString(version) {
		return fmt.Errorf("must be an exact semantic version (MAJOR.MINOR.PATCH), got %q", version)
	}
	return nil
}

// lockDigest hashes a lock file's contents so callers can detect whether a
// package-manager invocation actually changed anything. A missing lock
// file hashes to a distinct sentinel so "file appeared" also counts as a
// change.
func lockDigest(projectPath, lockFile string) (string, error) {
	data, err := os.ReadFile(filepath.Join(projectPath, lockFile))
	if os.IsNotExist(err) {
		return "<missing>", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", lockFile, err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// SpecUpdater executes only the reviewed argv and lock-file policy returned by
// a built-in adapter. Docker, egress, mounts, user, platform, and output limits
// remain owned by the core runner.
type SpecUpdater struct {
	Image string
	Spec  ecosystem.MutationSpec
	Run   DockerRunner
}

// NewSpecUpdater validates adapter output before any container can run.
func NewSpecUpdater(image string, spec ecosystem.MutationSpec, run DockerRunner) (SpecUpdater, error) {
	if image == "" || run == nil {
		return SpecUpdater{}, errors.New("ecosystem updater requires an image and core runner")
	}
	if spec.LockFile == "" || filepath.Base(spec.LockFile) != spec.LockFile || strings.ContainsAny(spec.LockFile, `/\`+"\x00") {
		return SpecUpdater{}, fmt.Errorf("ecosystem mutation lock file %q is not a root file", spec.LockFile)
	}
	if len(spec.Commands) == 0 {
		return SpecUpdater{}, errors.New("ecosystem mutation has no commands")
	}
	for commandIndex, command := range spec.Commands {
		if len(command) == 0 {
			return SpecUpdater{}, fmt.Errorf("ecosystem mutation command %d is empty", commandIndex)
		}
		for argumentIndex, argument := range command {
			if argument == "" || strings.ContainsRune(argument, '\x00') {
				return SpecUpdater{}, fmt.Errorf("ecosystem mutation command %d argument %d is invalid", commandIndex, argumentIndex)
			}
		}
	}
	return SpecUpdater{Image: image, Spec: spec, Run: run}, nil
}

func (u SpecUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	before, err := lockDigest(projectPath, u.Spec.LockFile)
	if err != nil {
		return false, err
	}
	for _, command := range u.Spec.Commands {
		if _, err := u.Run(ctx, u.Image, append([]string(nil), command...), projectPath); err != nil {
			return false, err
		}
	}
	after, err := lockDigest(projectPath, u.Spec.LockFile)
	if err != nil {
		return false, err
	}
	return before != after, nil
}
