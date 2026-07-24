package configinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestProjectGitignoreAddsOnlyExactAnchoredRuleAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".gitignore")
	original := "# keep\r\n.vuelta*\r\nnested/.vuelta/\r\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanProjectGitignore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed || string(plan.Updated) != original+"/.vuelta/\r\n" {
		t.Fatalf("updated .gitignore = %q", plan.Updated)
	}
	if err := plan.Apply(path); err != nil {
		t.Fatal(err)
	}
	repeated, err := PlanProjectGitignore(root)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Changed {
		t.Fatal("exact anchored rule was added twice")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original+"/.vuelta/\r\n" || !strings.Contains(string(data), ".vuelta*") {
		t.Fatalf("existing patterns were changed: %q", data)
	}
}

func TestProjectGitignorePreservesMissingFinalNewline(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".gitignore")
	if err := os.WriteFile(path, []byte("# keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanProjectGitignore(root)
	if err != nil {
		t.Fatal(err)
	}
	if string(plan.Updated) != "# keep\n/.vuelta/" || plan.Mode != 0o640 {
		t.Fatalf("plan = mode %04o data %q", plan.Mode, plan.Updated)
	}
}

func TestProjectGitignoreRejectsUnsafeTypesAndOversizedFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "ignore")
		if err := os.WriteFile(outside, []byte("keep\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, ".gitignore")); err != nil {
			t.Fatal(err)
		}
		if _, err := PlanProjectGitignore(root); err == nil {
			t.Fatal("symlink .gitignore was accepted")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, ".gitignore"), make([]byte, maxGitignoreBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := PlanProjectGitignore(root); err == nil {
			t.Fatal("oversized .gitignore was accepted")
		}
	})
}

func TestProjectOnboardingRestoresGitignoreWhenPolicyPublishFails(t *testing.T) {
	root := t.TempDir()
	ignorePath := filepath.Join(root, ".gitignore")
	if err := os.WriteFile(ignorePath, []byte("# original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ignorePlan, err := PlanProjectGitignore(root)
	if err != nil {
		t.Fatal(err)
	}
	projectPath := filepath.Join(root, ".vuelta.yaml")
	project := &config.ProjectConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		Workspace: config.Workspace{
			Path: ".", Stack: config.StackNode, PackageManager: "npm",
			Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
			AllowedChangedPaths: []string{"package.json", "package-lock.json"},
		},
	}
	projectPlan, err := PlanProjectConfigWrite(project, projectPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectPath, []byte("concurrent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyProjectOnboarding(&projectPlan, projectPath, ignorePlan, ignorePath); err == nil {
		t.Fatal("concurrent project policy did not fail onboarding")
	}
	data, err := os.ReadFile(ignorePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "# original\n" {
		t.Fatalf(".gitignore was not restored: %q", data)
	}
}
