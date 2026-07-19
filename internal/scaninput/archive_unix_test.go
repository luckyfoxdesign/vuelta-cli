//go:build unix

package scaninput

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestPythonRequirementsContractRejectsFIFO(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "requirements.txt")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), root, root, Options{}, PythonRequirementsContract())
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO input error = %v", err)
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatalf("FIFO fixture disappeared: %v", statErr)
	}
}
