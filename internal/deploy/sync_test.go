package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/githubactions"
	"github.com/luckyfoxdesign/vuelta/internal/history"
)

type fakeReleaseClient struct {
	dispatches int
	run        githubactions.Run
}

type countingRuntime struct {
	deploys int
}

func (r *countingRuntime) Deploy(
	context.Context,
	Contract,
	history.DeploymentRelease,
	time.Time,
) (history.DeploymentRelease, error) {
	r.deploys++
	return history.DeploymentRelease{}, nil
}

func (r *countingRuntime) Rollback(
	context.Context,
	Contract,
	history.DeploymentRelease,
	time.Time,
) (history.DeploymentRelease, error) {
	return history.DeploymentRelease{}, nil
}

func (f *fakeReleaseClient) DispatchRelease(
	_ context.Context,
	request githubactions.ReleaseDispatchRequest,
) (githubactions.Run, error) {
	f.dispatches++
	f.run = githubactions.Run{
		ID: 42, URL: "https://github.com/example/control/actions/runs/42",
		Status: "queued", HeadSHA: request.SourceCommit,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	return f.run, nil
}

func (f *fakeReleaseClient) GetRun(context.Context, string, int64) (githubactions.Run, error) {
	return f.run, nil
}

func (f *fakeReleaseClient) BranchHead(context.Context, string, string) (string, error) {
	return runtimeCommit, nil
}

func TestSyncProjectDiscoversDispatchesAndDoesNotDuplicateRelease(t *testing.T) {
	root, _ := deploymentGitFixture(t)
	commit := runtimeCommit
	stateParent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := history.Open(context.Background(), filepath.Join(stateParent, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	client := &fakeReleaseClient{}
	cfg := config.Config{
		Deploy: config.DeployConfig{Enabled: true},
		GithubActions: config.GithubActionsConfig{
			ReleaseRepository: "example/control", ReleaseWorkflow: "vuelta-release.yml",
			ReleaseRef: "main", RegistryUser: "example",
		},
	}
	workspace := config.Workspace{Name: "api", Path: root, Branch: "main", Remote: "origin"}
	now := time.Date(2026, 7, 30, 14, 0, 0, 0, time.UTC)
	result, err := SyncProject(context.Background(), workspace, cfg, store, client, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "building" || result.Commit != commit || client.dispatches != 1 {
		t.Fatalf("result=%#v dispatches=%d", result, client.dispatches)
	}

	client.run.Status = "completed"
	client.run.Conclusion = "success"
	client.run.UpdatedAt = now.Add(time.Minute)
	result, err = SyncProject(context.Background(), workspace, cfg, store, client, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ready" || client.dispatches != 1 {
		t.Fatalf("result=%#v dispatches=%d", result, client.dispatches)
	}
	result, err = SyncProject(context.Background(), workspace, cfg, store, client, nil, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ready" || client.dispatches != 1 {
		t.Fatalf("idempotent result=%#v dispatches=%d", result, client.dispatches)
	}
	releases, err := store.DeploymentReleases(context.Background(), "api", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 1 {
		t.Fatalf("releases = %#v", releases)
	}
}

func TestContinueReleaseDoesNotRepeatCompletedOrInterruptedDeployment(t *testing.T) {
	runtime := &countingRuntime{}
	contract := Contract{Project: "api", Commit: runtimeCommit, Fingerprint: "contract"}
	for _, state := range []string{"deployed", "pulling", "blocked"} {
		result, err := continueRelease(
			context.Background(),
			contract,
			history.DeploymentRelease{
				ProjectName: "api", SourceCommit: runtimeCommit,
				ContractFingerprint: "contract", State: state,
			},
			nil,
			nil,
			runtime,
			time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("state %s: %v", state, err)
		}
		if state == "pulling" && !slices.Contains(result.Blockers, "deployment_recovery_required") {
			t.Fatalf("state %s result = %#v", state, result)
		}
		if state == "blocked" && !slices.Contains(result.Blockers, "operator_decision_required") {
			t.Fatalf("state %s result = %#v", state, result)
		}
	}
	if runtime.deploys != 0 {
		t.Fatalf("interrupted or completed releases were redeployed %d times", runtime.deploys)
	}
}

func deploymentGitFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "Dockerfile", "FROM scratch\n")
	writeFixture(t, root, "compose.yml", `
services:
  api:
    build: .
    container_name: api
    healthcheck:
      test: ["CMD", "check", "http://localhost:8000/health"]
`)
	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.email", "test@example.invalid"},
		{"config", "user.name", "Test"},
		{"add", "Dockerfile", "compose.yml"},
		{"commit", "-m", "fixture"},
		{"remote", "add", "origin", "https://github.com/example/api.git"},
	} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
		}
	}
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(output))
}
