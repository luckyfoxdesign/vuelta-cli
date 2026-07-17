package localexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutable(t *testing.T, root, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte("test executable"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveRejectsProjectAndWritableExecutables(t *testing.T) {
	project := t.TempDir()
	projectTool := writeExecutable(t, project, "npm", 0o700)
	writableTool := writeExecutable(t, t.TempDir(), "npm", 0o722)

	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "project", path: projectTool, want: "inside the target"},
		{name: "writable", path: writableTool, want: "group- or world-writable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Resolve(project, "npm", func(string) (string, error) { return test.path, nil })
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Resolve error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestResolveReturnsCanonicalAbsoluteTrustedExecutable(t *testing.T) {
	project := t.TempDir()
	toolRoot := t.TempDir()
	target := writeExecutable(t, toolRoot, "trusted-npm", 0o700)
	link := filepath.Join(toolRoot, "npm")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(project, "npm", func(name string) (string, error) {
		if name != "npm" {
			t.Fatalf("resolver name = %q", name)
		}
		return link, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want || !filepath.IsAbs(resolved) {
		t.Fatalf("resolved = %q, want canonical absolute %q", resolved, want)
	}
}

func TestResolveRejectsUnallowlistedNameBeforeLookup(t *testing.T) {
	called := false
	_, err := Resolve(t.TempDir(), "custom-scanner", func(string) (string, error) {
		called = true
		return "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") || called {
		t.Fatalf("Resolve error = %v, resolver called = %t", err, called)
	}
}

func TestEnvironmentIsPrivateMinimalAndRemoved(t *testing.T) {
	t.Setenv("PATH", "/hostile/bin")
	t.Setenv("HTTPS_PROXY", "http://hostile.invalid")
	t.Setenv("NPM_CONFIG_USERCONFIG", "/hostile/npmrc")
	t.Setenv("GITHUB_TOKEN", "must-not-leak")

	environment, err := NewEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	root := environment.Root()
	variables := environment.Variables()
	got := make(map[string]string, len(variables))
	for _, item := range variables {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			t.Fatalf("invalid environment entry %q", item)
		}
		got[name] = value
	}
	if got["PATH"] != CleanPath {
		t.Fatalf("PATH = %q, want fixed clean path", got["PATH"])
	}
	for _, forbidden := range []string{"HTTPS_PROXY", "NPM_CONFIG_USERCONFIG", "GITHUB_TOKEN"} {
		if _, ok := got[forbidden]; ok {
			t.Fatalf("hostile variable %s was inherited", forbidden)
		}
	}
	for _, path := range []string{root, got["HOME"], got["XDG_CACHE_HOME"], got["XDG_CONFIG_HOME"], got["TMPDIR"]} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("private path %q mode = %v", path, info.Mode())
		}
	}
	if err := environment.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private root still exists: %v", err)
	}
}

func TestRunStructuredHonorsHardLimitAndCancelledContext(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=TestLocalExecHelperProcess", "--", "output"}
	_, err = RunStructured(context.Background(), binary, t.TempDir(), args, []string{"GO_WANT_LOCAL_EXEC_HELPER=1"}, 32, 16)
	var limitErr *OutputLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("RunStructured error = %v, want output limit", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RunStructured(ctx, binary, t.TempDir(), args, []string{"GO_WANT_LOCAL_EXEC_HELPER=1"}, 32, 16)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunStructured cancellation error = %v", err)
	}
}

func TestLocalExecHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_LOCAL_EXEC_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString(strings.Repeat("x", 128))
	_, _ = os.Stderr.WriteString(strings.Repeat("e", 64))
}

func TestClassifyRedactsAndBoundsNonZeroExitDetail(t *testing.T) {
	result := Result{ExitCode: 1, Stderr: []byte("permission denied: token=abc123secret")}
	category, detail := Classify(nil, result)
	if category != "permission" {
		t.Fatalf("category = %q, want permission", category)
	}
	if strings.Contains(detail, "abc123secret") {
		t.Fatalf("detail leaked secret: %q", detail)
	}
}

func TestClassifyOutputLimitAndContextErrors(t *testing.T) {
	if category, _ := Classify(&OutputLimitError{Bytes: 10}, Result{}); category != "output_limit" {
		t.Fatalf("output limit category = %q", category)
	}
	if category, _ := Classify(context.DeadlineExceeded, Result{}); category != "timeout" {
		t.Fatalf("deadline category = %q", category)
	}
	if category, _ := Classify(context.Canceled, Result{}); category != "cancelled" {
		t.Fatalf("cancel category = %q", category)
	}
}
