package toolchain

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

type cacheDocker struct {
	images map[string]string
	builds int
	fail   bool
}

func (d *cacheDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *cacheDocker) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	if len(request.Args) >= 3 && request.Args[0] == "image" && request.Args[1] == "inspect" {
		imageID, ok := d.images[request.Args[len(request.Args)-1]]
		if !ok {
			return dockerexec.Result{}, errors.New("not found")
		}
		return dockerexec.Result{Stdout: []byte(imageID + "\n")}, nil
	}
	if len(request.Args) > 0 && request.Args[0] == "build" {
		if d.fail {
			return dockerexec.Result{}, errors.New("build failed")
		}
		d.builds++
		for index, argument := range request.Args {
			if argument == "--tag" && index+1 < len(request.Args) {
				d.images[request.Args[index+1]] = "sha256:" + strings.Repeat("a", 64)
			}
		}
		return dockerexec.Result{}, nil
	}
	return dockerexec.Result{}, errors.New("unexpected docker request")
}

func TestPrepareBuildCacheUsesContentHash(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":"24.x"},"packageManager":"npm@11.4.2"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	workspace := config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm", Platform: "linux/amd64"}
	docker := &cacheDocker{images: map[string]string{}}

	first, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Prepare(context.Background(), workspace, config.Config{}, docker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Built || first.Cached || second.Built || !second.Cached || docker.builds != 1 || first.CacheKey != second.CacheKey {
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
	_, err := Prepare(context.Background(), workspace, config.Config{}, &cacheDocker{images: map[string]string{}, fail: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "build embedded scanner image") {
		t.Fatalf("Prepare error = %v", err)
	}
}
