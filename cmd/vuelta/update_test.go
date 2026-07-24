package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/adhoc"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

func updateDefinition(t *testing.T) commandDefinition {
	t.Helper()
	for _, definition := range commandDefinitions {
		if reflect.DeepEqual(definition.path, []string{"update"}) {
			return definition
		}
	}
	t.Fatal("update command definition not found")
	return commandDefinition{}
}

func TestUpdateAcceptsDirectoryAndOptionalProjectLocalSnapshot(t *testing.T) {
	definition := updateDefinition(t)
	for _, args := range [][]string{
		{"--dry-run", "--json"},
		{"--snapshot", "abcdefghijklmnopqrstuv", "--dry-run", "--json"},
		{"--dry-run", "--json", "--directory", "/project", "--snapshot", "abcdefghijklmnopqrstuv"},
	} {
		normalized, err := normalizeCommandArgs(definition, args)
		if err != nil {
			t.Fatalf("normalize %v: %v", args, err)
		}
		options, id, err := parseUpdateOptions(normalized)
		if err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		if id != "" && id != "abcdefghijklmnopqrstuv" || !options.dryRun || !options.jsonOutput {
			t.Fatalf("parsed update = id %q options %#v", id, options)
		}
	}
	if _, _, err := parseUpdateOptions([]string{"legacy-id"}); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("positional-ID error = %v", err)
	}
}

func TestUpdateAutomationFlagsAreIndependent(t *testing.T) {
	options, _, err := parseUpdateOptions([]string{"--json", "--non-interactive", "--snapshot", "abcdefghijklmnopqrstuv"})
	if err != nil {
		t.Fatal(err)
	}
	if options.yes || !options.jsonOutput || !options.nonInteractive {
		t.Fatalf("--json or --non-interactive implied confirmation: %#v", options)
	}
	options, _, err = parseUpdateOptions([]string{"--yes", "--snapshot", "abcdefghijklmnopqrstuv"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.yes || options.jsonOutput || options.nonInteractive {
		t.Fatalf("--yes changed unrelated automation controls: %#v", options)
	}
}

func TestLoadUpdateConfigurationDoesNotWalkToParentProjectPolicy(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &config.ProjectConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		Workspace: config.Workspace{
			Path: ".", Stack: config.StackNode, PackageManager: "npm",
			Verification:        config.VerificationProfile{Version: config.VerificationVersion, State: config.VerificationScanOnly},
			AllowedChangedPaths: []string{"package.json", "package-lock.json"},
		},
	}
	projectPath := filepath.Join(parent, projectConfigName)
	plan, err := configinit.PlanProjectConfigWrite(project, projectPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(projectPath); err != nil {
		t.Fatal(err)
	}
	machinePath := filepath.Join(t.TempDir(), "config.yaml")
	if err := configinit.Write(configinit.NewConfig(), machinePath, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUpdateConfiguration(child, machinePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Workspaces) != 0 {
		t.Fatalf("parent project policy was discovered: %#v", cfg.Workspaces)
	}
}

func TestBuildUpdatePlanIsDeterministicAndShowsAllGates(t *testing.T) {
	snapshot := updatesnapshot.Snapshot{
		ID: "abcdefghijklmnopqrstuv", Origin: updatesnapshot.OriginAdhoc, AdhocPath: "/project",
		Gates: updatesnapshot.ScanGates{AllowProjectConfig: true, MinReleaseAge: "168h0m0s"},
		Candidates: []updatesnapshot.Candidate{
			{Kind: "npm", Name: "zeta", Current: "1.0.0", Target: "2.0.0"},
			{Kind: "npm", Name: "alpha", Current: "1.0.0", Target: "2.0.0"},
		},
	}
	project := adhoc.Project{Root: "/project", Manager: "npm", Manifest: "package.json", Lock: "package-lock.json"}
	plan := buildUpdatePlan(snapshot, nil, project, config.Config{}, updateOptions{allowScripts: true, allowUnverifiedReleaseAge: true})
	if got, want := plan.Files, []string{"package-lock.json", "package.json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
	if plan.Candidates[0].Name != "alpha" || plan.Candidates[1].Name != "zeta" {
		t.Fatalf("candidate order is not deterministic: %#v", plan.Candidates)
	}
	for _, gate := range []string{"lifecycle_scripts", "project_config", "minimum_release_age", "release_age", "execution", "durable_writes"} {
		if plan.SecurityGates[gate] == "" {
			t.Fatalf("missing effective security gate %q in %#v", gate, plan.SecurityGates)
		}
	}
	if len(plan.Tests) != 1 || !strings.Contains(plan.Tests[0], "disabled") || plan.Commit || plan.Push != "disabled" {
		t.Fatalf("adhoc action plan = %#v", plan)
	}
}
