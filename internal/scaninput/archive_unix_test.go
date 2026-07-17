//go:build unix

package scaninput

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildRejectsUnixSocket(t *testing.T) {
	root := initRepo(t)
	listener, err := net.Listen("unix", filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close Unix socket: %v", err)
		}
	}()

	contract := Contract{Stage: StageDockerManifest, Files: []File{{Path: "Dockerfile", Category: CategoryDockerManifest}}}
	_, err = Build(context.Background(), root, root, Options{}, contract)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("socket input error = %v", err)
	}
}
