// Package verificationprep materializes only lockfile-bound package
// dependencies needed by an approved verification command. Preparation runs
// in the snapshot-selected toolchain container with managed registry egress;
// the later verification container remains offline.
package verificationprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"gopkg.in/yaml.v3"
)

const defaultTimeout = 10 * time.Minute

const cacheDirectory = ".vuelta-verify-cache"

var immutableImage = regexp.MustCompile(`^(?:sha256:[0-9a-f]{64}|[^\s@]+@sha256:[0-9a-f]{64})$`)

// Kind classifies preparation errors without exposing package-manager output.
type Kind string

const (
	KindFailed        Kind = "failed"
	KindTimedOut      Kind = "timed_out"
	KindInputsChanged Kind = "inputs_changed"
)

// Error is a bounded, typed preparation failure. The pipeline reports only
// its stage externally; Err is retained for the private local diagnostic.
type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string {
	return fmt.Sprintf("verification dependency preparation %s: %v", e.Kind, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Preparer owns one exact snapshot-resolved package toolchain and frozen
// install contract. Run and Timeout are injectable only for deterministic
// tests; production constructors bind them to the hardened Docker runner.
type Preparer struct {
	workspace          config.Workspace
	profile            config.ToolchainProfile
	spec               ecosystem.VerificationDependencySpec
	allowManagerConfig bool
	run                updater.DockerRunner
	timeout            time.Duration
}

// New validates and binds the exact toolchain profile selected by the update
// snapshot. It never resolves a tag or silently chooses another platform.
func New(
	workspace config.Workspace,
	profile config.ToolchainProfile,
	egress config.EgressConfig,
	allowManagerConfig bool,
	docker dockerexec.Runner,
) (*Preparer, error) {
	if profile.Stack != workspace.Stack || profile.PackageManager != workspace.PackageManager {
		return nil, errors.New("verification dependency toolchain does not match the selected workspace")
	}
	if profile.Platform == "" || profile.User == "" || !immutableImage.MatchString(profile.Image) {
		return nil, errors.New("verification dependency toolchain is not immutable and fully constrained")
	}
	registry, err := catalog.New()
	if err != nil {
		return nil, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	adapter, err := registry.Lookup(workspace.Stack, workspace.PackageManager)
	if err != nil {
		return nil, err
	}
	provider, ok := adapter.(ecosystem.VerificationDependencyProvider)
	if !ok {
		return nil, &ecosystem.CapabilityError{Key: adapter.Key(), Capability: "verification-dependencies"}
	}
	spec := provider.VerificationDependencies()
	if len(spec.Command) == 0 {
		return nil, errors.New("verification dependency contract has no command")
	}
	return &Preparer{
		workspace: workspace, profile: profile, spec: spec, allowManagerConfig: allowManagerConfig,
		run:     updater.NewDockerRunnerWithProfile(docker, egress, profile.User, profile.Platform),
		timeout: defaultTimeout,
	}, nil
}

// Prepare performs one frozen, lifecycle-script-disabled install and proves
// that every admitted manifest, lock, and manager-config input is unchanged.
func (p *Preparer) Prepare(ctx context.Context, workDir string) (returnErr error) {
	if p == nil || p.run == nil || p.timeout <= 0 {
		return &Error{Kind: KindFailed, Err: errors.New("preparer is not configured")}
	}
	cachePath := filepath.Join(workDir, cacheDirectory)
	if _, err := os.Lstat(cachePath); err == nil {
		return &Error{Kind: KindFailed, Err: errors.New("verification dependency cache path already exists")}
	} else if !errors.Is(err, os.ErrNotExist) {
		return &Error{Kind: KindFailed, Err: errors.New("inspect verification dependency cache path")}
	}
	defer func() {
		if err := os.RemoveAll(cachePath); err != nil && returnErr == nil {
			returnErr = &Error{Kind: KindFailed, Err: errors.New("remove verification dependency cache")}
		}
	}()
	if err := p.validateRootInputs(workDir); err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}
	before, err := p.inputBundle(ctx, workDir)
	if err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}
	defer before.Destroy()
	if err := validateBoundPackageData(p.workspace.PackageManager, before); err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}

	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	_, runErr := p.run(runCtx, p.profile.Image, append([]string(nil), p.spec.Command...), workDir)
	timedOut := runCtx.Err() == context.DeadlineExceeded
	cancel()
	if timedOut {
		return &Error{Kind: KindTimedOut, Err: errors.New("frozen install exceeded its time limit")}
	}
	if runErr != nil {
		return &Error{Kind: KindFailed, Err: runErr}
	}

	after, err := p.inputBundle(ctx, workDir)
	if err != nil {
		return &Error{Kind: KindInputsChanged, Err: err}
	}
	defer after.Destroy()
	if before.Manifest.Hash != after.Manifest.Hash {
		return &Error{Kind: KindInputsChanged, Err: errors.New("frozen install changed an admitted package input")}
	}
	return nil
}

func (p *Preparer) validateRootInputs(root string) error {
	if !p.allowManagerConfig {
		for _, name := range p.spec.ManagerConfigFiles {
			present, err := regularRootFilePresent(root, name)
			if err != nil {
				return err
			}
			if present {
				return errors.New("unreviewed package-manager configuration is not allowed")
			}
		}
	}
	for _, name := range p.spec.UnsupportedFiles {
		present, err := regularRootFilePresent(root, name)
		if err != nil {
			return err
		}
		if present {
			return errors.New("workspace-style dependency preparation is not supported")
		}
	}
	return nil
}

func regularRootFilePresent(root, name string) (bool, error) {
	info, err := os.Lstat(filepath.Join(root, name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("inspect verification dependency input")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("verification dependency input must be a regular root file")
	}
	return true, nil
}

func (p *Preparer) inputBundle(ctx context.Context, workDir string) (scaninput.Bundle, error) {
	workspace := p.workspace
	workspace.Path = workDir
	contract, err := scaninput.PackageContract(workspace, p.allowManagerConfig)
	if err != nil {
		return scaninput.Bundle{}, err
	}
	return scaninput.Build(ctx, workDir, workDir, scaninput.Options{}, contract)
}

func validateBoundPackageData(manager string, bundle scaninput.Bundle) error {
	manifest, ok := bundle.Content("package.json")
	if !ok {
		return errors.New("package manifest is missing from the preparation contract")
	}
	var document struct {
		Workspaces   json.RawMessage   `json:"workspaces"`
		Dependencies map[string]string `json:"dependencies"`
		Dev          map[string]string `json:"devDependencies"`
		Optional     map[string]string `json:"optionalDependencies"`
		Peer         map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(manifest, &document); err != nil {
		return errors.New("parse package manifest for dependency preparation")
	}
	if len(document.Workspaces) > 0 && string(document.Workspaces) != "null" && string(document.Workspaces) != "[]" {
		return errors.New("workspace-style dependency preparation is not supported")
	}
	for _, dependencies := range []map[string]string{document.Dependencies, document.Dev, document.Optional, document.Peer} {
		for _, value := range dependencies {
			if localReference(value) {
				return errors.New("local-path package dependencies are not supported for isolated verification")
			}
		}
	}

	var lock []byte
	switch manager {
	case "npm":
		lock, ok = bundle.Content("package-lock.json")
		if !ok {
			lock, ok = bundle.Content("npm-shrinkwrap.json")
		}
		if !ok {
			return errors.New("npm lockfile is missing from the preparation contract")
		}
		var value any
		if err := json.Unmarshal(lock, &value); err != nil {
			return errors.New("parse npm lockfile for dependency preparation")
		}
		if containsLocalReference(value) {
			return errors.New("local-path lockfile entries are not supported for isolated verification")
		}
	case "pnpm":
		lock, ok = bundle.Content("pnpm-lock.yaml")
		if !ok {
			return errors.New("pnpm lockfile is missing from the preparation contract")
		}
		var value any
		if err := yaml.Unmarshal(lock, &value); err != nil {
			return errors.New("parse pnpm lockfile for dependency preparation")
		}
		if containsLocalReference(value) {
			return errors.New("local-path lockfile entries are not supported for isolated verification")
		}
	default:
		return errors.New("package manager has no verification dependency parser")
	}
	return nil
}

func containsLocalReference(value any) bool {
	switch typed := value.(type) {
	case string:
		return localReference(typed)
	case []any:
		for _, item := range typed {
			if containsLocalReference(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if key == "link" {
				if linked, ok := item.(bool); ok && linked {
					return true
				}
			}
			if containsLocalReference(item) {
				return true
			}
		}
	case map[any]any:
		for key, item := range typed {
			if stringKey, ok := key.(string); ok && localReference(stringKey) {
				return true
			}
			if containsLocalReference(item) {
				return true
			}
		}
	}
	return false
}

func localReference(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "link:") || strings.HasPrefix(lower, "workspace:")
}
