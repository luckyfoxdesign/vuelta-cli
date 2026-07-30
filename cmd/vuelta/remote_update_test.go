package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/updatepolicy"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

func TestResolveUpdateSubcommandsAndProjectPositionals(t *testing.T) {
	definition, args, err := resolveCommand([]string{"update", "status", "api", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if definition.handler != "update status" || !reflect.DeepEqual(args, []string{"api", "--json"}) {
		t.Fatalf("resolved status = handler %q args %#v", definition.handler, args)
	}
	definition, args, err = resolveCommand([]string{"update", "api", "--yes"})
	if err != nil {
		t.Fatal(err)
	}
	if definition.handler != "update" || !reflect.DeepEqual(args, []string{"api", "--yes"}) {
		t.Fatalf("resolved update = handler %q args %#v", definition.handler, args)
	}
}

func TestBuildRemoteUpdatePlanSeparatesRoutineAndDeferred(t *testing.T) {
	now := time.Now().UTC()
	workspace := config.Workspace{Github: &config.GithubWorkflow{
		Repository: "example/api", Workflow: "vuelta-update.yml",
	}}
	snapshot := updatesnapshot.Snapshot{
		ID:        "abcdefghijklmnopqrstuv",
		Workspace: updatesnapshot.WorkspaceIdentity{BaseRevision: testFullCommit},
		Candidates: []updatesnapshot.Candidate{
			{
				Kind: "npm", Name: "routine", Current: "1.0.0", Target: "1.1.0",
				Direct: true, Stable: true, VersionClass: updatepolicy.ClassMinor,
				PolicyDisposition: updatepolicy.DispositionRoutine,
			},
			{
				Kind: "npm", Name: "major", Current: "1.0.0", Target: "2.0.0",
				Direct: true, Stable: true, VersionClass: updatepolicy.ClassMajor,
				PolicyDisposition: updatepolicy.DispositionDeferred, EligibleAt: now.Add(-time.Hour),
			},
			{
				Kind: "npm", Name: "transitive", Current: "1.0.0", Target: "1.0.1",
				Stable: true, VersionClass: updatepolicy.ClassPatch,
				PolicyDisposition: updatepolicy.DispositionDeferred,
			},
		},
	}
	routine, err := buildRemoteUpdatePlan("api", workspace, snapshot, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(routine.RoutineCandidates) != 1 || len(routine.DeferredCandidates) != 2 {
		t.Fatalf("routine plan = %#v", routine)
	}
	withMajor, err := buildRemoteUpdatePlan("api", workspace, snapshot, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(withMajor.RoutineCandidates) != 2 || len(withMajor.DeferredCandidates) != 1 {
		t.Fatalf("major plan = %#v", withMajor)
	}
}

func TestRoutineSnapshotCandidatesRejectUnknownAndTransitive(t *testing.T) {
	candidates := []updatesnapshot.Candidate{
		{Name: "routine", Direct: true, Stable: true, PolicyDisposition: updatepolicy.DispositionRoutine},
		{Name: "unknown", Direct: true, Stable: true, VersionClass: updatepolicy.ClassUnknown, PolicyDisposition: updatepolicy.DispositionDeferred},
		{Name: "transitive", Stable: true, PolicyDisposition: updatepolicy.DispositionRoutine},
	}
	selected := routineSnapshotCandidates(candidates, false, time.Now().UTC())
	if len(selected) != 1 || selected[0].Name != "routine" {
		t.Fatalf("selected candidates = %#v", selected)
	}
}

func TestExactUpdateWorkspaceUsesVersionedGitHubIdentity(t *testing.T) {
	root := t.TempDir()
	projectConfig := `schema_version: 1
workspace:
  path: .
  stack: node
  package_manager: pnpm
  branch: main
  remote: origin
  github:
    repository: versioned/api
    workflow: versioned-update.yml
  verification:
    version: 1
    state: scan_only
`
	if err := os.WriteFile(filepath.Join(root, projectConfigName), []byte(projectConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Workspaces: []config.Workspace{{
		Name: "api", Path: root, Stack: config.StackNode, PackageManager: "pnpm",
		Branch: "main", Remote: "origin", ToolchainProfile: "pinned",
		Github: &config.GithubWorkflow{Repository: "machine/ignored", Workflow: "ignored.yml"},
	}}}
	workspace, err := exactUpdateWorkspace(cfg, "api")
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Github.Repository != "versioned/api" || workspace.Github.Workflow != "versioned-update.yml" {
		t.Fatalf("GitHub identity = %#v", workspace.Github)
	}
	if workspace.ToolchainProfile != "pinned" {
		t.Fatalf("toolchain profile = %q", workspace.ToolchainProfile)
	}
}

const testFullCommit = "0123456789abcdef0123456789abcdef01234567"
