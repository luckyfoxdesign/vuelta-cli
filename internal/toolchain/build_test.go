package toolchain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	scannerimages "github.com/luckyfoxdesign/vuelta/scanner-images"
)

type cacheDocker struct {
	mu             sync.Mutex
	images         map[string]string
	builds         int
	buildDirs      []string
	smokes         int
	fail           bool
	failDetail     string
	failStdout     string
	failErr        error
	platform       string
	metadataUser   string
	scannerVersion string
}

func (d *cacheDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *cacheDocker) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(request.Args) >= 3 && request.Args[0] == "image" && request.Args[1] == "inspect" {
		imageID, ok := d.images[request.Args[len(request.Args)-1]]
		if !ok {
			return dockerexec.Result{}, errors.New("not found")
		}
		if len(request.Args) >= 5 && request.Args[2] == "--format" && request.Args[3] != "{{.Id}}" {
			platform := strings.SplitN(d.platform, "/", 2)
			metadata, _ := json.Marshal(builtImageMetadata{ID: imageID, OS: platform[0], Architecture: platform[1], User: d.metadataUser})
			return dockerexec.Result{Stdout: metadata}, nil
		}
		return dockerexec.Result{Stdout: []byte(imageID + "\n")}, nil
	}
	if len(request.Args) > 0 && request.Args[0] == "build" {
		d.buildDirs = append(d.buildDirs, request.Dir)
		if d.fail {
			err := d.failErr
			if err == nil {
				err = errors.New("build failed")
			}
			return dockerexec.Result{
				Stdout: []byte(d.failStdout), Stderr: []byte(d.failDetail),
			}, err
		}
		d.builds++
		for index, argument := range request.Args {
			switch {
			case argument == "--platform" && index+1 < len(request.Args):
				d.platform = request.Args[index+1]
			case argument == "--iidfile" && index+1 < len(request.Args):
				imageID := "sha256:" + strings.Repeat("a", 64)
				d.images[imageID] = imageID
				if err := os.WriteFile(request.Args[index+1], []byte(imageID+"\n"), 0o600); err != nil {
					return dockerexec.Result{}, err
				}
			case strings.HasPrefix(argument, "NCU_VERSION="):
				d.scannerVersion = strings.TrimPrefix(argument, "NCU_VERSION=")
			}
		}
		return dockerexec.Result{}, nil
	}
	if len(request.Args) == 4 && request.Args[0] == "image" && request.Args[1] == "tag" {
		imageID, ok := d.images[request.Args[2]]
		if !ok {
			return dockerexec.Result{}, errors.New("source image not found")
		}
		d.images[request.Args[3]] = imageID
		return dockerexec.Result{}, nil
	}
	if len(request.Args) > 0 && request.Args[0] == "run" {
		d.smokes++
		return dockerexec.Result{Combined: []byte(d.scannerVersion + "\n")}, nil
	}
	return dockerexec.Result{}, errors.New("unexpected docker request")
}

func TestPrepareBuildCacheUsesContentHash(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"24.x"},"packageManager":"npm@11.4.2"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	workspace := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	docker := &cacheDocker{images: map[string]string{}, metadataUser: "10001:10001"}

	first, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Built || first.Cached || second.Built || !second.Cached || docker.builds != 1 || docker.smokes != 1 || first.CacheKey != second.CacheKey {
		t.Fatalf("first=%#v second=%#v builds=%d", first, second, docker.builds)
	}
	if first.Identity.Source != SourceDefault || first.Identity.ImageID != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("identity = %#v", first.Identity)
	}

	write(t, root, "package.json", `{"engines":{"node":"24.x"},"packageManager":"npm@11.5.0"}`)
	changed, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed.Built || changed.CacheKey == first.CacheKey || docker.builds != 2 {
		t.Fatalf("changed=%#v builds=%d", changed, docker.builds)
	}
}

func TestPrepareReportsBuildFailure(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"22.x"}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	workspace := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/arm64"}
	_, err := Prepare(context.Background(), workspace, config.Config{}, &cacheDocker{images: map[string]string{}, metadataUser: "10001:10001", fail: true}, nil)
	var buildErr *BuildError
	if !errors.As(err, &buildErr) || buildErr.Kind != BuildFailureDocker {
		t.Fatalf("Prepare error = %v", err)
	}
}

func TestPrepareClassifiesPNPMBuildFailures(t *testing.T) {
	tests := []struct {
		name, detail, stdout string
		err                  error
		want                 BuildFailureKind
	}{
		{"missing version", "npm error code ETARGET\nNo matching version found for pnpm@10.999.0", "", errors.New("build failed"), BuildFailureVersionUnavailable},
		{"registry network", "npm error network request to registry failed with EAI_AGAIN", "", errors.New("build failed"), BuildFailureRegistry},
		{"buildkit stdout", "", "#9 ERROR: process did not complete successfully", errors.New("build failed"), BuildFailureDocker},
		{"cancelled", "", "", context.Canceled, BuildFailureCancelled},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "package.json", `{"engines":{"node":"22.x"},"packageManager":"pnpm@10.14.0"}`)
			write(t, root, "pnpm-lock.yaml", `lockfileVersion: '9.0'`)
			workspace := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "pnpm", Platform: "linux/amd64"}
			docker := &cacheDocker{
				images: map[string]string{}, metadataUser: "10001:10001",
				fail: true, failDetail: testCase.detail,
				failStdout: testCase.stdout, failErr: testCase.err,
			}
			_, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
			var buildErr *BuildError
			if !errors.As(err, &buildErr) || buildErr.Kind != testCase.want ||
				buildErr.Manager != "pnpm" || buildErr.Version != "10.14.0" ||
				len(buildErr.Detail) > 1024 {
				t.Fatalf("Prepare error = %#v, %v", buildErr, err)
			}
			if len(docker.buildDirs) != 1 {
				t.Fatalf("build directories = %q", docker.buildDirs)
			}
			if _, statErr := os.Stat(docker.buildDirs[0]); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("temporary build directory remains after failure: %v", statErr)
			}
		})
	}
}

func TestPrepareCoalescesConcurrentContentAddressedBuilds(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"24.x"},"packageManager":"npm@11.4.2"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	workspace := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	docker := &cacheDocker{images: map[string]string{}, metadataUser: "10001:10001"}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
			results <- err
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if docker.builds != 1 || docker.smokes != 1 {
		t.Fatalf("builds=%d smokes=%d, want one validated build", docker.builds, docker.smokes)
	}
}

func TestPNPMScannerImageDisablesLifecycleScriptsAndRunsNonRoot(t *testing.T) {
	data, err := scannerimages.Files.ReadFile("node-pnpm.Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"--ignore-scripts", "npm_config_ignore_scripts=true",
		"PNPM_CONFIG_IGNORE_SCRIPTS=true", "USER 10001:10001",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("node-pnpm.Dockerfile missing %q", required)
		}
	}
}

func TestPrepareRejectsScannerContractBeforePublishingCacheTag(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"22.x"}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	workspace := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	docker := &cacheDocker{images: map[string]string{}, metadataUser: "0:0"}
	_, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Prepare error = %v", err)
	}
	for image := range docker.images {
		if strings.HasPrefix(image, "vuelta-scanner-cache:") {
			t.Fatalf("invalid image was published as %q", image)
		}
	}
}

func TestMatchesScannerVersion(t *testing.T) {
	for _, testCase := range []struct {
		stack, manager, scanner, version, output string
		want                                     bool
	}{
		{"node", "npm", "ncu", "22.2.9", "22.2.9", true},
		{"node", "pnpm", "pnpm", "9.15.0", "9.15.0", true},
		{"python", "poetry", "poetry", "2.1.1", "Poetry (version 2.1.1)", true},
		{"python", "uv", "uv", "0.6.14", "uv 0.6.14 (abcdef 2025-01-01)", true},
		{"python", "uv", "uv", "0.6.14", "uv 0.6.140", false},
		{"unknown", "manager", "unknown", "1.0.0", "1.0.0", false},
	} {
		profile := config.ToolchainProfile{
			Stack: testCase.stack, PackageManager: testCase.manager,
			Scanner: testCase.scanner, ScannerVersion: testCase.version,
		}
		if got := matchesScannerVersion(profile, testCase.output); got != testCase.want {
			t.Fatalf("matchesScannerVersion(%q, %q, %q) = %t", testCase.scanner, testCase.version, testCase.output, got)
		}
	}
}
