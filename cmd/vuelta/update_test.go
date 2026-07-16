package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/localupdate"
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

func TestUpdateAcceptsFlagsBeforeOrAfterExactlyOneSnapshotID(t *testing.T) {
	definition := updateDefinition(t)
	for _, args := range [][]string{
		{"--dry-run", "--json", "abcdefghijklmnopqrstuv"},
		{"abcdefghijklmnopqrstuv", "--dry-run", "--json"},
	} {
		normalized, err := normalizeCommandArgs(definition, args)
		if err != nil {
			t.Fatalf("normalize %v: %v", args, err)
		}
		options, id, err := parseUpdateOptions(normalized)
		if err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		if id != "abcdefghijklmnopqrstuv" || !options.dryRun || !options.jsonOutput {
			t.Fatalf("parsed update = id %q options %#v", id, options)
		}
	}
	if _, _, err := parseUpdateOptions([]string{"one", "two"}); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("two-ID error = %v", err)
	}
}

func TestUpdateAutomationFlagsAreIndependent(t *testing.T) {
	options, _, err := parseUpdateOptions([]string{"--json", "--non-interactive", "abcdefghijklmnopqrstuv"})
	if err != nil {
		t.Fatal(err)
	}
	if options.yes || !options.jsonOutput || !options.nonInteractive {
		t.Fatalf("--json or --non-interactive implied confirmation: %#v", options)
	}
	options, _, err = parseUpdateOptions([]string{"--yes", "abcdefghijklmnopqrstuv"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.yes || options.jsonOutput || options.nonInteractive {
		t.Fatalf("--yes changed unrelated automation controls: %#v", options)
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
	project := localupdate.Project{Root: "/project", Manager: "npm", Manifest: "package.json", Lock: "package-lock.json"}
	plan := buildUpdatePlan(snapshot, nil, project, config.Config{}, updateOptions{execution: "local", allowScripts: true, allowUnverifiedReleaseAge: true})
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
