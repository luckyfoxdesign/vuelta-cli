package toolchain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

type cacheDocker struct {
	images         map[string]string
	builds         int
	smokes         int
	fail           bool
	platform       string
	metadataUser   string
	scannerVersion string
}

func (d *cacheDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *cacheDocker) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
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
		if d.fail {
			return dockerexec.Result{}, errors.New("build failed")
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
	if err == nil || !strings.Contains(err.Error(), "build embedded scanner image") {
		t.Fatalf("Prepare error = %v", err)
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
		scanner, version, output string
		want                     bool
	}{
		{"ncu", "22.2.9", "22.2.9", true},
		{"pnpm", "9.15.0", "9.15.0", true},
		{"poetry", "2.1.1", "Poetry (version 2.1.1)", true},
		{"uv", "0.6.14", "uv 0.6.14 (abcdef 2025-01-01)", true},
		{"uv", "0.6.14", "uv 0.6.140", false},
		{"unknown", "1.0.0", "1.0.0", false},
	} {
		if got := matchesScannerVersion(testCase.scanner, testCase.version, testCase.output); got != testCase.want {
			t.Fatalf("matchesScannerVersion(%q, %q, %q) = %t", testCase.scanner, testCase.version, testCase.output, got)
		}
	}
}
