//go:build !windows

package dockerexec

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpointValidationRejectsNonLocalAndMissingSocketsWithoutLeakingPath(t *testing.T) {
	endpoint := testEndpoint()
	endpoint.SocketPath = "tcp://attacker.invalid:2375"
	if _, err := validateEndpoint(endpoint); err == nil || !strings.Contains(err.Error(), "absolute local path") {
		t.Fatalf("non-local endpoint error = %v", err)
	}
	endpoint.SocketPath = filepath.Join(t.TempDir(), "private-endpoint-name.sock")
	_, err := validateEndpoint(endpoint)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing endpoint error = %v", err)
	}
	if strings.Contains(err.Error(), "private-endpoint-name") {
		t.Fatalf("endpoint error leaked configured path: %v", err)
	}
}
