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
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	scannerimages "github.com/luckyfoxdesign/vuelta/scanner-images"
)

const scannerBuildTimeout = 20 * time.Minute

var localImageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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
		Profile config.ToolchainProfile `json:"profile"`
		Build   buildSpec               `json:"build"`
		Files   []embeddedEntry         `json:"files"`
	}{Profile: selection.Profile, Build: *selection.build, Files: entries}
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
	args := []string{"build", "--platform", selection.Profile.Platform, "--tag", tag, "--file", filepath.Join("scanner-images", selection.build.Dockerfile)}
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
	_, err = docker.Run(buildCtx, dockerexec.Request{
		Args: args, Dir: root,
		Stdout: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 8 << 10},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 16 << 10},
	})
	if err != nil {
		category, exitCode, detail := dockerexec.Classify(err)
		if detail != "" {
			return fmt.Errorf("build embedded scanner image failed (%s, exit %d): %s", category, exitCode, detail)
		}
		return fmt.Errorf("build embedded scanner image failed (%s, exit %d)", category, exitCode)
	}
	return nil
}
