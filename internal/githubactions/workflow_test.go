package githubactions

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReusableWorkflowIsParseablePinnedAndNonDeploying(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/vuelta-update-engine.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse reusable workflow: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"workflow_call:", "cooldown_days:", "include_major:", "contents: write",
		"pull-requests: write", "--routine-only", "--min-release-age 14d",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("workflow lacks %q", required)
		}
	}
	for _, forbidden := range []string{"deploy", "ssh", "GHCR", "secrets: inherit", "pull_request_target"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("workflow contains forbidden capability %q", forbidden)
		}
	}
	actionPin := regexp.MustCompile(`uses: actions/[A-Za-z0-9_-]+@[0-9a-f]{40}`)
	if count := len(actionPin.FindAll(data, -1)); count != 3 {
		t.Fatalf("pinned first-party action uses = %d, want 3", count)
	}
}

func TestExampleWrapperExposesOnlyVersionedInputs(t *testing.T) {
	data, err := os.ReadFile("../../deploy/vuelta-update.example.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse example workflow: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "secrets:") || strings.Contains(text, "run:") {
		t.Fatal("example wrapper exposes secrets or executable steps")
	}
	for _, input := range []string{"request_id:", "base_commit:", "policy_version:", "cooldown_days:", "include_major:"} {
		if !strings.Contains(text, input) {
			t.Fatalf("example wrapper lacks %q", input)
		}
	}
}
