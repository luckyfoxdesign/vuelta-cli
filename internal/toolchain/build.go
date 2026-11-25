package toolchain

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
	scannerimages "github.com/luckyfoxdesign/vuelta/scanner-images"
)

const scannerBuildTimeout = 20 * time.Minute

const (
	scannerBuildContractVersion = 2
	scannerValidationTimeout    = 2 * time.Minute
)

var localImageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var scannerBuildLocks sync.Map

type buildSpec struct {
	Dockerfile string
	Args       map[string]string
}

// Prepared is a scan-ready selection. Profile.Image is either the configured
// immutable override or the local image ID produced from embedded inputs.
type Prepared struct {
	Selection
	Identity Identity
	CacheKey string
	Built    bool
	Cached   bool
}

// Prepare selects a profile and builds an embedded default on first use.
// announce is called immediately before the potentially slow local build.
func Prepare(ctx context.Context, ws config.Workspace, cfg config.Config, docker dockerexec.Runner, announce func(string)) (Prepared, error) {
	selection, err := Select(ws, cfg)
	if err != nil {
		return Prepared{}, err
	}
	return prepareSelection(ctx, selection, docker, announce)
}

// PrepareForFix resolves a repair-capable adapter independently of latest
// discovery. In particular Bun repairs use native bun, without running ncu.
func PrepareForFix(ctx context.Context, ws config.Workspace, cfg config.Config, docker dockerexec.Runner, announce func(string)) (Prepared, error) {
	constraints, err := Detect(ws)
	if err != nil {
		return Prepared{}, err
	}
	registry, err := catalog.New()
	if err != nil {
		return Prepared{}, err
	}
	adapter, err := registry.Lookup(ws.Stack, ws.PackageManager)
	if err != nil {
		return Prepared{}, err
	}
	provider, ok := adapter.(ecosystem.FixProvider)
	if !ok {
		return Prepared{}, errors.New("adapter has no vulnerability repair capability")
	}
	runtimeConstraint, err := ecosystem.ParseRuntimeConstraint(constraints.Stack, constraints.Runtime)
	if err != nil {
		return Prepared{}, err
	}
	profile, found, err := selectOverride(ws, cfg.Update.ToolchainProfiles, constraints, runtimeConstraint)
	if err != nil {
		return Prepared{}, err
	}
	selection := Selection{Profile: profile, Constraints: constraints, RuntimeConstraint: runtimeConstraint.Canonical(), Source: SourceOverride}
	if !found {
		spec, err := provider.FixToolchain(ecosystem.Constraints{Key: adapter.Key(), Runtime: constraints.Runtime, PackageManagerVersion: constraints.PackageManagerVersion, LockFormat: constraints.LockFormat, Platform: constraints.Platform})
		if err != nil {
			return Prepared{}, err
		}
		if spec.Key != adapter.Key() || !exactVersionPattern.MatchString(spec.PackageManagerVersion) {
			return Prepared{}, errors.New("invalid repair toolchain contract")
		}
		selection.Profile = config.ToolchainProfile{Version: config.ToolchainProfileVersion, ID: spec.ID, Stack: spec.Key.Stack, PackageManager: spec.Key.PackageManager,
			Runtime: spec.Runtime, PackageManagerVersion: spec.PackageManagerVersion, Scanner: spec.Scanner, ScannerVersion: spec.ScannerVersion,
			Platform: spec.Platform, User: spec.User, LockFormats: append([]string(nil), spec.LockFormats...), Capabilities: config.ToolchainCapabilities{ReadOnlyDiscovery: spec.Capabilities.ReadOnlyDiscovery}}
		selection.Source = SourceDefault
		selection.build = &buildSpec{Dockerfile: spec.Dockerfile, Args: spec.BuildArgs}
	}
	return prepareSelection(ctx, selection, docker, announce)
}

func prepareSelection(ctx context.Context, selection Selection, docker dockerexec.Runner, announce func(string)) (Prepared, error) {
	if selection.Source == SourceOverride {
		identity, identityErr := IdentityForResolvedProfile(selection.Profile, selection.Source, selection.Profile.Image)
		if identityErr != nil {
			return Prepared{}, identityErr
		}
		return Prepared{Selection: selection, Identity: identity}, nil
	}
	cacheKey, err := buildCacheKey(selection)
	if err != nil {
		return Prepared{}, err
	}
	tag := "vuelta-scanner-cache:" + cacheKey
	if imageID, inspectErr := InspectImageID(ctx, docker, tag); inspectErr == nil {
		selection.Profile.Image = imageID
		identity, identityErr := IdentityForResolvedProfile(selection.Profile, selection.Source, imageID)
		if identityErr != nil {
			return Prepared{}, identityErr
		}
		return Prepared{Selection: selection, Identity: identity, CacheKey: cacheKey, Cached: true}, nil
	}
	lockValue, _ := scannerBuildLocks.LoadOrStore(cacheKey, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	// A concurrent workspace may have completed the same content-addressed
	// build while this caller was waiting.
	if imageID, inspectErr := InspectImageID(ctx, docker, tag); inspectErr == nil {
		selection.Profile.Image = imageID
		identity, identityErr := IdentityForResolvedProfile(selection.Profile, selection.Source, imageID)
		if identityErr != nil {
			return Prepared{}, identityErr
		}
		return Prepared{Selection: selection, Identity: identity, CacheKey: cacheKey, Cached: true}, nil
	}
	if announce != nil {
		announce(fmt.Sprintf("building %s locally for %s (cache %s)", selection.Profile.ID, selection.Profile.Platform, cacheKey[:12]))
	}
	if err := buildDefault(ctx, docker, selection, tag); err != nil {
		return Prepared{}, err
	}
	imageID, err := InspectImageID(ctx, docker, tag)
	if err != nil {
		return Prepared{}, fmt.Errorf("inspect locally built scanner image: %w", err)
	}
	selection.Profile.Image = imageID
	identity, err := IdentityForResolvedProfile(selection.Profile, selection.Source, imageID)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{Selection: selection, Identity: identity, CacheKey: cacheKey, Built: true}, nil
}

// InspectImageID returns Docker's content-addressed local image ID.
func InspectImageID(ctx context.Context, docker dockerexec.Runner, image string) (string, error) {
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"image", "inspect", "--format", "{{.Id}}", image},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 256},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return "", errors.New("scanner image is not present in the approved Docker daemon")
	}
	imageID := strings.TrimSpace(string(result.Stdout))
	if !localImageIDPattern.MatchString(imageID) {
		return "", errors.New("approved Docker daemon returned a malformed scanner image ID")
	}
	return imageID, nil
}

func buildCacheKey(selection Selection) (string, error) {
	entries, err := embeddedEntries()
	if err != nil {
		return "", err
	}
	payload := struct {
		Contract int                     `json:"contract"`
		Profile  config.ToolchainProfile `json:"profile"`
		Build    buildSpec               `json:"build"`
		Files    []embeddedEntry         `json:"files"`
	}{Contract: scannerBuildContractVersion, Profile: selection.Profile, Build: *selection.build, Files: entries}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode scanner build inputs: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

type embeddedEntry struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

func embeddedEntries() ([]embeddedEntry, error) {
	directory, err := fs.ReadDir(scannerimages.Files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded scanner inputs: %w", err)
	}
	entries := make([]embeddedEntry, 0, len(directory))
	for _, item := range directory {
		if item.IsDir() || (!strings.HasSuffix(item.Name(), ".Dockerfile") && !strings.HasSuffix(item.Name(), ".py")) {
			continue
		}
		data, readErr := scannerimages.Files.ReadFile(item.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read embedded scanner input %s: %w", item.Name(), readErr)
		}
		entries = append(entries, embeddedEntry{Name: item.Name(), Data: data})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func buildDefault(ctx context.Context, docker dockerexec.Runner, selection Selection, tag string) error {
	if selection.build == nil {
		return errors.New("default scanner build recipe is missing")
	}
	root, err := os.MkdirTemp("", "vuelta-scanner-build-")
	if err != nil {
		return fmt.Errorf("create scanner build context: %w", err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	scannerDir := filepath.Join(root, "scanner-images")
	if err := os.Mkdir(scannerDir, 0o700); err != nil {
		return fmt.Errorf("create embedded scanner directory: %w", err)
	}
	entries, err := embeddedEntries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.WriteFile(filepath.Join(scannerDir, entry.Name), entry.Data, 0o600); err != nil {
			return fmt.Errorf("materialize embedded scanner input %s: %w", entry.Name, err)
		}
	}
	iidPath := filepath.Join(root, "image.id")
	args := []string{"build", "--pull", "--progress", "plain", "--platform", selection.Profile.Platform, "--file", filepath.Join("scanner-images", selection.build.Dockerfile), "--iidfile", iidPath}
	argNames := make([]string, 0, len(selection.build.Args))
	for name := range selection.build.Args {
		argNames = append(argNames, name)
	}
	sort.Strings(argNames)
	for _, name := range argNames {
		args = append(args, "--build-arg", name+"="+selection.build.Args[name])
	}
	args = append(args, ".")
	buildCtx, cancel := context.WithTimeout(ctx, scannerBuildTimeout)
	defer cancel()
	result, err := docker.Run(buildCtx, dockerexec.Request{
		Args: args, Dir: root,
		Stdout: dockerexec.Capture{Mode: dockerexec.Excerpt, Bytes: 8 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Excerpt, Bytes: 16 << 10},
	})
	if err != nil {
		return classifyBuildError(selection.Profile, result, err)
	}
	iid, err := os.ReadFile(iidPath)
	if err != nil {
		return fmt.Errorf("read locally built scanner image ID: %w", err)
	}
	imageID := strings.TrimSpace(string(iid))
	if !localImageIDPattern.MatchString(imageID) {
		return errors.New("local scanner build returned a malformed image ID")
	}
	if err := validateBuiltDefault(ctx, docker, selection.Profile, imageID); err != nil {
		return err
	}
	if _, err := docker.Run(ctx, dockerexec.Request{
		Args:   []string{"image", "tag", imageID, tag},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	}); err != nil {
		return fmt.Errorf("publish validated scanner cache tag: %w", err)
	}
	return nil
}

func classifyBuildError(profile config.ToolchainProfile, result dockerexec.Result, err error) error {
	category, exitCode, classifiedDetail := dockerexec.Classify(err)
	detailBytes := append([]byte(nil), result.Stderr...)
	if len(result.Stdout) > 0 {
		if len(detailBytes) > 0 {
			detailBytes = append(detailBytes, "\n[vuelta: build stdout]\n"...)
		}
		detailBytes = append(detailBytes, result.Stdout...)
	}
	detail := safeerr.Excerpt(detailBytes, 1024)
	if detail == "" {
		detail = classifiedDetail
	}
	lower := strings.ToLower(detail)
	kind := BuildFailureDocker
	switch {
	case errors.Is(err, context.Canceled) || category == safeerr.CategoryCancelled:
		kind = BuildFailureCancelled
	case strings.Contains(lower, "etarget") || strings.Contains(lower, "notarget") ||
		strings.Contains(lower, "no matching version found") ||
		strings.Contains(lower, "version not found"):
		kind = BuildFailureVersionUnavailable
	case category == safeerr.CategoryEndpoint || category == safeerr.CategoryEgress ||
		strings.Contains(lower, "eai_again") || strings.Contains(lower, "enotfound") ||
		strings.Contains(lower, "econnreset") || strings.Contains(lower, "network request") ||
		strings.Contains(lower, "fetch failed") || strings.Contains(lower, "registry unavailable"):
		kind = BuildFailureRegistry
	}
	return &BuildError{
		Kind: kind, Manager: profile.PackageManager, Version: profile.PackageManagerVersion,
		Category: category, ExitCode: exitCode, Detail: detail, Unwrapped: err,
	}
}

type builtImageMetadata struct {
	ID           string `json:"id"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	User         string `json:"user"`
}

// validateBuiltDefault runs only while refreshing an embedded image, before
// the content-addressed cache tag is published. Live scans therefore reuse a
// previously validated local image instead of repeating startup probes.
func validateBuiltDefault(ctx context.Context, docker dockerexec.Runner, profile config.ToolchainProfile, imageID string) error {
	validationCtx, cancel := context.WithTimeout(ctx, scannerValidationTimeout)
	defer cancel()
	format := `{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}}}`
	result, err := docker.Run(validationCtx, dockerexec.Request{
		Args:   []string{"image", "inspect", "--format", format, imageID},
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 1024},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return fmt.Errorf("inspect built scanner contract: %w", err)
	}
	var metadata builtImageMetadata
	if err := json.Unmarshal(result.Stdout, &metadata); err != nil {
		return errors.New("approved Docker daemon returned malformed scanner metadata")
	}
	wantOS, wantArch, ok := strings.Cut(profile.Platform, "/")
	if !ok || wantOS == "" || wantArch == "" {
		return fmt.Errorf("toolchain profile %q has invalid platform %q", profile.ID, profile.Platform)
	}
	if metadata.ID != imageID || metadata.OS != wantOS || metadata.Architecture != wantArch {
		return fmt.Errorf("built scanner identity/platform mismatch for profile %q", profile.ID)
	}
	if metadata.User != profile.User {
		return fmt.Errorf("built scanner user %q does not match profile %q user %q", metadata.User, profile.ID, profile.User)
	}

	smokeArgs := []string{
		"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--user", profile.User, "--platform", profile.Platform,
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", imageID, profile.Scanner, "--version",
	}
	smoke, err := docker.Run(validationCtx, dockerexec.Request{
		Args: smokeArgs, Combined: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: 4 << 10},
	})
	if err != nil {
		category, exitCode, detail := dockerexec.Classify(err)
		if detail != "" {
			return fmt.Errorf("validate hardened scanner startup failed (%s, exit %d): %s", category, exitCode, detail)
		}
		return fmt.Errorf("validate hardened scanner startup failed (%s, exit %d)", category, exitCode)
	}
	if !matchesScannerVersion(profile, strings.TrimSpace(string(smoke.Combined))) {
		return fmt.Errorf("scanner %q did not report expected version %q", profile.Scanner, profile.ScannerVersion)
	}
	return nil
}

func matchesScannerVersion(profile config.ToolchainProfile, output string) bool {
	registry, err := catalog.New()
	if err != nil {
		return false
	}
	adapter, err := registry.Lookup(profile.Stack, profile.PackageManager)
	if err != nil {
		return false
	}
	provider, ok := adapter.(ecosystem.ProfilePolicyProvider)
	if !ok {
		return false
	}
	policy := provider.ProfilePolicy()
	if policy.ExpectedScanner != profile.Scanner {
		return false
	}
	switch policy.VersionOutputStyle {
	case "exact":
		return output == profile.ScannerVersion
	case "contains-version":
		return strings.Contains(output, "version "+profile.ScannerVersion)
	case "prefix-name-version":
		prefix := profile.Scanner + " " + profile.ScannerVersion
		return strings.HasPrefix(output, prefix) && (len(output) == len(prefix) || output[len(prefix)] == ' ')
	default:
		return false
	}
}
