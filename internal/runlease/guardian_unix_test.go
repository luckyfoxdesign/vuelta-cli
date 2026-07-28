//go:build unix

package runlease

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGuardianSurvivesForcedParentTermination(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	readyPath := filepath.Join(root, "ready")
	cleanedPath := filepath.Join(root, "cleaned")
	parent := exec.Command(executable, "-test.run=TestGuardianForcedParentHelper")
	parent.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"VUELTA_GUARDIAN_TEST_MODE=parent",
		"VUELTA_GUARDIAN_READY=" + readyPath,
		"VUELTA_GUARDIAN_CLEANED=" + cleanedPath,
	}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, readyPath)
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	waitForFile(t, cleanedPath)
}

func TestGuardianForcedParentHelper(t *testing.T) {
	switch os.Getenv("VUELTA_GUARDIAN_TEST_MODE") {
	case "parent":
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.run=TestGuardianForcedParentHelper")
		child.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"VUELTA_GUARDIAN_TEST_MODE=child",
			"VUELTA_GUARDIAN_CLEANED=" + os.Getenv("VUELTA_GUARDIAN_CLEANED"),
		}
		guardian, err := startGuardianCommand(child)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("VUELTA_GUARDIAN_READY"), []byte("ready\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Second)
			_ = guardian
		}
	case "child":
		parentPipe := os.NewFile(uintptr(3), "test-parent-lease")
		if parentPipe == nil {
			t.Fatal("missing parent lease")
		}
		defer func() { _ = parentPipe.Close() }()
		cleanup, err := WaitForParent(parentPipe)
		if err != nil {
			t.Fatal(err)
		}
		if !cleanup {
			t.Fatal("forced parent exit was marked clean")
		}
		if err := os.WriteFile(os.Getenv("VUELTA_GUARDIAN_CLEANED"), []byte("cleaned\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuardianCleanFinishSuppressesRecovery(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=TestGuardianCleanChild")
	child.Env = []string{"PATH=" + os.Getenv("PATH"), "VUELTA_GUARDIAN_TEST_MODE=clean-child"}
	guardian, err := startGuardianCommand(child)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := guardian.Finish(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func TestGuardianCleanChild(t *testing.T) {
	if os.Getenv("VUELTA_GUARDIAN_TEST_MODE") != "clean-child" {
		return
	}
	parentPipe := os.NewFile(uintptr(3), "test-parent-lease")
	if parentPipe == nil {
		t.Fatal("missing parent lease")
	}
	defer func() { _ = parentPipe.Close() }()
	cleanup, err := WaitForParent(parentPipe)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup {
		t.Fatal("clean finish requested recovery")
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", filepath.Base(path))
}
