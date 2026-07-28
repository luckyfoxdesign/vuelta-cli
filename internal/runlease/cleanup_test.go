package runlease

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

type cleanupDocker struct {
	calls      [][]string
	listOutput map[string]string
}

func (d *cleanupDocker) Path() (string, error) { return "/usr/bin/docker", nil }

func (d *cleanupDocker) Run(_ context.Context, request dockerexec.Request) (dockerexec.Result, error) {
	args := append([]string(nil), request.Args...)
	d.calls = append(d.calls, args)
	if len(args) >= 2 && args[1] == "ls" {
		key := args[0] + "/" + filterValue(args, ResourceLabel)
		return dockerexec.Result{Stdout: []byte(d.listOutput[key])}, nil
	}
	return dockerexec.Result{}, nil
}

func filterValue(args []string, label string) string {
	prefix := "label=" + label + "="
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	return ""
}

func TestCleanupUsesExactLifecycleFiltersAndPreservesUnlistedResources(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	containerID := strings.Repeat("b", 64)
	imageID := "sha256:" + strings.Repeat("c", 64)
	networkID := strings.Repeat("d", 64)
	persistentID := strings.Repeat("e", 64)
	docker := &cleanupDocker{listOutput: map[string]string{
		"container/" + ResourceScannerFinal: containerID + "\n",
		"image/" + ResourceScannerInput:     imageID + "\n",
		"network/" + ResourceEgressNetwork:  networkID + "\n",
	}}
	if err := Cleanup(context.Background(), docker, invocation); err != nil {
		t.Fatal(err)
	}
	for _, call := range docker.calls {
		if len(call) < 2 || call[1] != "ls" {
			continue
		}
		for _, required := range []string{
			"label=" + ContractLabel + "=" + ContractValue,
			"label=" + InvocationLabel + "=" + invocation,
		} {
			if !contains(call, required) {
				t.Fatalf("cleanup list call lacks exact filter %q: %v", required, call)
			}
		}
	}
	removed := removedIDs(docker.calls)
	if !reflect.DeepEqual(removed, []string{containerID, imageID, networkID}) {
		t.Fatalf("removed IDs = %v", removed)
	}
	if contains(removed, persistentID) {
		t.Fatalf("persistent resource %q was targeted", persistentID)
	}
}

func TestCleanupRejectsMalformedDaemonResourceIDWithoutRemovingIt(t *testing.T) {
	docker := &cleanupDocker{listOutput: map[string]string{
		"container/" + ResourceScannerFinal: "--foreign-option\n",
	}}
	err := Cleanup(context.Background(), docker, strings.Repeat("a", 32))
	if err == nil || !strings.Contains(err.Error(), "invalid owned resource ID") {
		t.Fatalf("Cleanup error = %v", err)
	}
	for _, call := range docker.calls {
		if len(call) >= 2 && (call[1] == "rm" || call[0] == "rm") {
			t.Fatalf("malformed ID reached remove command: %v", call)
		}
	}
}

func TestCleanupRejectsInvalidInvocationBeforeDocker(t *testing.T) {
	docker := &cleanupDocker{}
	if err := Cleanup(context.Background(), docker, "not-an-invocation"); err == nil {
		t.Fatal("invalid invocation was accepted")
	}
	if len(docker.calls) != 0 {
		t.Fatalf("Docker was called: %v", docker.calls)
	}
}

func removedIDs(calls [][]string) []string {
	var ids []string
	for _, call := range calls {
		if len(call) < 3 || call[1] != "rm" {
			continue
		}
		ids = append(ids, call[len(call)-1])
	}
	return ids
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
