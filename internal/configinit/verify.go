package configinit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"gopkg.in/yaml.v3"
)

// VerifyCPUs, VerifyMemLimit, and VerifyPidsLimit are the fixed resource
// limits applied to every generated compose.verify.yml service. They are
// collected here as the single edit point for the adaptive scanner memory
// budget follow-up (docs/backlog/todo/28-07-26-app-adaptive-scanner-memory-budget.md).
const (
	VerifyCPUs      = "1"
	VerifyMemLimit  = "1g"
	VerifyPidsLimit = 256
)

// verifyComposeDoc is the plain Compose document written to disk. It is a
// distinct, minimal type from testrunner's validated model: the generator
// only ever emits fields testrunner.validateCompose already allows, and the
// file is re-validated through that exact policy before it is written.
type verifyComposeDoc struct {
	Services map[string]verifyComposeService `yaml:"services"`
	Networks map[string]verifyComposeNetwork `yaml:"networks"`
}

type verifyComposeService struct {
	Image       string                 `yaml:"image"`
	Platform    string                 `yaml:"platform,omitempty"`
	User        string                 `yaml:"user"`
	ReadOnly    bool                   `yaml:"read_only"`
	WorkingDir  string                 `yaml:"working_dir"`
	Environment map[string]string      `yaml:"environment"`
	Volumes     []verifyComposeVolume  `yaml:"volumes"`
	Tmpfs       []string               `yaml:"tmpfs"`
	CapDrop     []string               `yaml:"cap_drop"`
	SecurityOpt []string               `yaml:"security_opt"`
	CPUs        string                 `yaml:"cpus"`
	MemLimit    string                 `yaml:"mem_limit"`
	PidsLimit   int                    `yaml:"pids_limit"`
	Networks    []string               `yaml:"networks"`
	Command     []string               `yaml:"command"`
}

type verifyComposeVolume struct {
	Type   string `yaml:"type"`
	Source string `yaml:"source"`
	Target string `yaml:"target"`
}

type verifyComposeNetwork struct {
	Internal bool `yaml:"internal"`
}

// GenerateVerifyCompose detects the project's verify-capable package
// manager, resolves its digest-pinned base image, selects a safe package
// script, and renders a hardened compose.verify.yml document. It performs no
// writes: WriteVerifyCompose validates and persists the result.
func GenerateVerifyCompose(ctx context.Context, root, scriptOverride string, resolve updater.DigestResolver) ([]byte, string, error) {
	discovery, err := Detect(root)
	if err != nil {
		return nil, "", err
	}
	adapter, err := selectVerifyAdapter(discovery)
	if err != nil {
		return nil, "", err
	}
	envProvider := adapter.(ecosystem.VerificationEnvironmentProvider)

	detected, err := toolchain.Detect(config.Workspace{
		Path: discovery.Root, Stack: adapter.Key().Stack, PackageManager: adapter.Key().PackageManager,
	})
	if err != nil {
		return nil, "", err
	}
	spec, err := adapter.(ecosystem.ToolchainProvider).DefaultToolchain(ecosystem.Constraints{
		Key: adapter.Key(), Runtime: detected.Runtime, RuntimeConstraintSource: detected.RuntimeConstraintSource,
		PackageManagerVersion: detected.PackageManagerVersion, LockFormat: detected.LockFormat, Platform: detected.Platform,
	})
	if err != nil {
		return nil, "", err
	}
	baseImage := spec.BuildArgs["BASE_IMAGE"]
	if baseImage == "" {
		return nil, "", fmt.Errorf("adapter %s has no verify base image", adapter.Key().String())
	}
	digest, err := resolve(ctx, baseImage)
	if err != nil {
		return nil, "", fmt.Errorf("resolve digest for %s: %w", baseImage, err)
	}

	scripts, err := packageScripts(discovery.Root)
	if err != nil {
		return nil, "", err
	}
	scriptName, err := chooseVerifyScript(scripts, scriptOverride)
	if err != nil {
		return nil, "", err
	}
	command := adapter.(ecosystem.VerificationProvider).VerificationCommand(scriptName)

	doc := verifyComposeDoc{
		Services: map[string]verifyComposeService{
			"verify": {
				Image: baseImage + "@" + digest, Platform: spec.Platform, User: spec.User, ReadOnly: true,
				WorkingDir:  "/workspace",
				Environment: envProvider.VerificationEnvironment(),
				Volumes:     []verifyComposeVolume{{Type: "bind", Source: ".", Target: "/workspace"}},
				Tmpfs:       []string{"/tmp:rw,noexec,nosuid,nodev,size=64m"},
				CapDrop:     []string{"ALL"},
				SecurityOpt: []string{"no-new-privileges:true"},
				CPUs:        VerifyCPUs, MemLimit: VerifyMemLimit, PidsLimit: VerifyPidsLimit,
				Networks: []string{"verification"}, Command: command,
			},
		},
		Networks: map[string]verifyComposeNetwork{"verification": {Internal: true}},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("serialize compose.verify.yml: %w", err)
	}
	return data, scriptName, nil
}

// WriteVerifyCompose generates, validates through the same fail-closed
// policy path used before a real verification run, and atomically writes
// compose.verify.yml. It refuses to overwrite an existing file and leaves no
// file on disk when generation or validation fails.
func WriteVerifyCompose(ctx context.Context, root, scriptOverride string, resolve updater.DigestResolver) (path, scriptName string, err error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve project path: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", "", fmt.Errorf("resolve project path: %w", err)
	}
	target := filepath.Join(absRoot, "compose.verify.yml")
	if _, statErr := os.Lstat(target); statErr == nil {
		return "", "", fmt.Errorf("%s already exists; refusing to overwrite", target)
	} else if !os.IsNotExist(statErr) {
		return "", "", fmt.Errorf("inspect %s: %w", target, statErr)
	}

	data, scriptName, err := GenerateVerifyCompose(ctx, absRoot, scriptOverride, resolve)
	if err != nil {
		return "", "", err
	}
	if err := validateGeneratedCompose(absRoot, data); err != nil {
		return "", "", fmt.Errorf("generated compose.verify.yml failed policy validation: %w", err)
	}
	if err := writeNewAtomic(target, data, 0o644); err != nil {
		return "", "", err
	}
	return target, scriptName, nil
}

// validateGeneratedCompose re-parses the rendered document through the exact
// policy path a real verification run uses, so the generator can only ever
// write a file it would itself accept. The check runs against a temporary
// sandbox-relative file that is always removed before returning.
func validateGeneratedCompose(root string, data []byte) error {
	temp, err := os.CreateTemp(root, ".compose.verify.yml.check-*")
	if err != nil {
		return fmt.Errorf("prepare validation file: %w", err)
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write validation file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("write validation file: %w", err)
	}
	rel, err := filepath.Rel(root, name)
	if err != nil {
		return fmt.Errorf("resolve validation file: %w", err)
	}
	return testrunner.ValidateComposeService(root, rel, "verify")
}

// selectVerifyAdapter restricts generation to stacks with a reviewed verify
// template: only an adapter implementing ecosystem.VerificationEnvironmentProvider
// qualifies. Absence of any candidate, or more than one, fails closed instead
// of guessing.
func selectVerifyAdapter(discovery Discovery) (ecosystem.Adapter, error) {
	registry, err := catalog.New()
	if err != nil {
		return nil, err
	}
	var candidates []ecosystem.Adapter
	for _, stack := range discovery.Stacks {
		for _, manager := range discovery.PackageManagers[stack] {
			adapter, lookupErr := registry.Lookup(stack, manager)
			if lookupErr != nil {
				continue
			}
			if _, ok := adapter.(ecosystem.VerificationEnvironmentProvider); ok {
				candidates = append(candidates, adapter)
			}
		}
	}
	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("no verify template exists yet for detected stack(s) %s; write compose.verify.yml manually", strings.Join(discovery.Stacks, ", "))
	case 1:
		return candidates[0], nil
	default:
		names := make([]string, len(candidates))
		for i, adapter := range candidates {
			names[i] = adapter.Key().String()
		}
		return nil, fmt.Errorf("multiple verify-capable package managers detected (%s); write compose.verify.yml manually", strings.Join(names, ", "))
	}
}

// chooseVerifyScript selects the package.json script the generated service
// runs. An explicit override must name a present, safe script. Otherwise
// exactly one safe candidate among the fixed verification factories is
// required; zero or more than one fails closed and names the rejected or
// available candidates.
func chooseVerifyScript(scripts map[string]string, override string) (string, error) {
	if override != "" {
		body, ok := scripts[override]
		if !ok {
			return "", fmt.Errorf("--script %q was not found in package.json scripts", override)
		}
		if !safePackageScript(body) {
			return "", fmt.Errorf("--script %q is not a safe verification script", override)
		}
		return override, nil
	}
	var safe []string
	var rejected []string
	for _, factory := range verificationFactories {
		body, ok := scripts[factory]
		if !ok {
			continue
		}
		if safePackageScript(body) {
			safe = append(safe, factory)
		} else {
			rejected = append(rejected, factory)
		}
	}
	switch len(safe) {
	case 0:
		if len(rejected) == 0 {
			return "", fmt.Errorf("package.json has no safe %s script; rerun with --script NAME", strings.Join(verificationFactories, ", "))
		}
		return "", fmt.Errorf("package.json script(s) %s are not safe verification candidates; rerun with --script NAME", strings.Join(rejected, ", "))
	case 1:
		return safe[0], nil
	default:
		return "", &MissingValueError{Flag: "--script", Options: safe}
	}
}
