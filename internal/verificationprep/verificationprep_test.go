package verificationprep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/egress"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
)

func writeInput(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func npmInputs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeInput(t, root, "package.json", `{
  "name":"clean-verification",
  "scripts":{"build":"node build.js"},
  "dependencies":{"lodash":"4.17.20"}
}`)
	writeInput(t, root, "package-lock.json", `{
  "name":"clean-verification",
  "lockfileVersion":3,
  "packages":{
    "":{"dependencies":{"lodash":"4.17.20"}},
    "node_modules/lodash":{
      "version":"4.17.20",
      "resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    }
  }
}`)
	return root
}

func npmPreparer(run updater.DockerRunner) *Preparer {
	return &Preparer{
		workspace: config.Workspace{Path: "/tracked/project", Stack: config.StackNode, PackageManager: "npm"},
		profile: config.ToolchainProfile{
			Stack: config.StackNode, PackageManager: "npm", Image: "sha256:" + strings.Repeat("a", 64),
			Platform: "linux/amd64", User: "10001:10001",
		},
		spec: ecosystem.VerificationDependencySpec{
			Command:            []string{"npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache=/project/.vuelta-verify-cache/npm"},
			ManagerConfigFiles: []string{".npmrc"},
		},
		run: run, timeout: time.Second,
	}
}

func TestPrepareMaterializesDependenciesFromFrozenLifecycleDisabledCommand(t *testing.T) {
	root := npmInputs(t)
	called := false
	preparer := npmPreparer(func(_ context.Context, image string, args []string, workDir string) (string, error) {
		called = true
		if image != "sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("image = %q", image)
		}
		want := []string{"npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache=/project/.vuelta-verify-cache/npm"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
		if _, err := os.Stat(filepath.Join(workDir, "node_modules")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preparation copied host dependencies before install: %v", err)
		}
		writeInput(t, workDir, "node_modules/lodash/lodash.js", "module.exports = {}\n")
		writeInput(t, workDir, cacheDirectory+"/npm/cache-entry", "ephemeral\n")
		return "installed", nil
	})

	if err := preparer.Prepare(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("frozen dependency command was not run")
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules/lodash/lodash.js")); err != nil {
		t.Fatalf("prepared dependency artifact is unavailable to verification: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, cacheDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dependency download cache remained visible to verification: %v", err)
	}
}

func TestPrepareRejectsPackageInputMutation(t *testing.T) {
	root := npmInputs(t)
	preparer := npmPreparer(func(_ context.Context, _ string, _ []string, workDir string) (string, error) {
		writeInput(t, workDir, "package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
		return "", nil
	})

	err := preparer.Prepare(context.Background(), root)
	var prepareErr *Error
	if !errors.As(err, &prepareErr) || prepareErr.Kind != KindInputsChanged {
		t.Fatalf("Prepare() error = %v, want inputs_changed", err)
	}
}

func TestPrepareReportsDeniedEgressWithoutFallingBack(t *testing.T) {
	root := npmInputs(t)
	preparer := npmPreparer(func(context.Context, string, []string, string) (string, error) {
		return "", egress.ErrPolicyUnavailable
	})

	err := preparer.Prepare(context.Background(), root)
	var prepareErr *Error
	if !errors.As(err, &prepareErr) || prepareErr.Kind != KindFailed || !errors.Is(err, egress.ErrPolicyUnavailable) {
		t.Fatalf("Prepare() error = %v, want failed egress policy", err)
	}
}

func TestPrepareDistinguishesTimeoutAndCancellation(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		preparer := npmPreparer(func(ctx context.Context, _ string, _ []string, _ string) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		})
		preparer.timeout = time.Millisecond
		err := preparer.Prepare(context.Background(), npmInputs(t))
		var prepareErr *Error
		if !errors.As(err, &prepareErr) || prepareErr.Kind != KindTimedOut {
			t.Fatalf("Prepare() error = %v, want timed_out", err)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := npmPreparer(func(context.Context, string, []string, string) (string, error) {
			t.Fatal("runner must not start after cancellation")
			return "", nil
		}).Prepare(ctx, npmInputs(t))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Prepare() error = %v, want context cancellation", err)
		}
	})
}

func TestPrepareBindsOrRejectsManagerConfiguration(t *testing.T) {
	root := npmInputs(t)
	writeInput(t, root, ".npmrc", "registry=https://registry.npmjs.org/\n")
	called := false
	preparer := npmPreparer(func(context.Context, string, []string, string) (string, error) {
		called = true
		return "", nil
	})
	if err := preparer.Prepare(context.Background(), root); err == nil || called {
		t.Fatalf("unreviewed manager config was accepted: %v", err)
	}

	preparer.allowManagerConfig = true
	if err := preparer.Prepare(context.Background(), root); err != nil {
		t.Fatalf("snapshot-bound manager config was rejected: %v", err)
	}
}

func TestPrepareRejectsInputsThatExpandBeyondTheBoundRootContract(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
	}{
		{name: "workspace", manifest: `{"workspaces":["packages/*"],"dependencies":{"lodash":"4.17.20"}}`},
		{name: "local dependency", manifest: `{"dependencies":{"shared":"file:../shared"}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := npmInputs(t)
			writeInput(t, root, "package.json", test.manifest)
			called := false
			preparer := npmPreparer(func(context.Context, string, []string, string) (string, error) {
				called = true
				return "", nil
			})
			if err := preparer.Prepare(context.Background(), root); err == nil || called {
				t.Fatalf("expanded input contract was accepted: %v", err)
			}
		})
	}
}
