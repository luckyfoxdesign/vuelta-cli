package runlease

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

const cleanupListLimit = 16 << 10

var dockerResourceID = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)

type cleanupSpec struct {
	kind       string
	owner      string
	resource   string
	listArgs   []string
	removeArgs []string
}

var cleanupSpecs = []cleanupSpec{
	{
		kind: "scanner input containers", owner: OwnerScanner, resource: ResourceScannerInput,
		listArgs:   []string{"container", "ls", "--all", "--quiet", "--no-trunc"},
		removeArgs: []string{"container", "rm", "--force"},
	},
	{
		kind: "scanner database initializers", owner: OwnerScanner, resource: ResourceScannerDB,
		listArgs:   []string{"container", "ls", "--all", "--quiet", "--no-trunc"},
		removeArgs: []string{"container", "rm", "--force"},
	},
	{
		kind: "scanner containers", owner: OwnerScanner, resource: ResourceScannerFinal,
		listArgs:   []string{"container", "ls", "--all", "--quiet", "--no-trunc"},
		removeArgs: []string{"container", "rm", "--force"},
	},
	{
		kind: "managed egress proxies", owner: OwnerManagedEgress, resource: ResourceEgressProxy,
		listArgs:   []string{"container", "ls", "--all", "--quiet", "--no-trunc"},
		removeArgs: []string{"container", "rm", "--force"},
	},
	{
		kind: "scanner input images", owner: OwnerScanner, resource: ResourceScannerInput,
		listArgs:   []string{"image", "ls", "--quiet", "--no-trunc"},
		removeArgs: []string{"image", "rm", "--force"},
	},
	{
		kind: "managed egress networks", owner: OwnerManagedEgress, resource: ResourceEgressNetwork,
		listArgs:   []string{"network", "ls", "--quiet", "--no-trunc"},
		removeArgs: []string{"network", "rm"},
	},
}

// Cleanup removes only resources carrying the exact ownership, lifecycle,
// invocation, and resource labels for invocation.
func Cleanup(ctx context.Context, docker dockerexec.Runner, invocation string) error {
	if docker == nil {
		return errors.New("docker cleanup runner is required")
	}
	if !ValidID(invocation) {
		return errors.New("invalid Docker cleanup invocation identity")
	}
	var cleanupErrors []error
	for _, spec := range cleanupSpecs {
		ids, err := listIDs(ctx, docker, spec, invocation)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("list %s: %w", spec.kind, err))
			continue
		}
		if len(ids) == 0 {
			continue
		}
		args := append(append([]string(nil), spec.removeArgs...), ids...)
		if _, err := docker.Run(ctx, dockerexec.Request{
			Args:   args,
			Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
		}); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove %s: %w", spec.kind, err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func listIDs(ctx context.Context, docker dockerexec.Runner, spec cleanupSpec, invocation string) ([]string, error) {
	args := append([]string(nil), spec.listArgs...)
	for _, filter := range []string{
		OwnerLabel + "=" + spec.owner,
		ContractLabel + "=" + ContractValue,
		InvocationLabel + "=" + invocation,
		ResourceLabel + "=" + spec.resource,
	} {
		args = append(args, "--filter", "label="+filter)
	}
	result, err := docker.Run(ctx, dockerexec.Request{
		Args:   args,
		Stdout: dockerexec.Capture{Mode: dockerexec.Limit, Bytes: cleanupListLimit},
		Stderr: dockerexec.Capture{Mode: dockerexec.Tail, Bytes: 4 << 10},
	})
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) > 128 {
		return nil, errors.New("approved Docker daemon returned too many owned resource IDs")
	}
	ids := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, id := range fields {
		if !dockerResourceID.MatchString(id) {
			return nil, errors.New("approved Docker daemon returned an invalid owned resource ID")
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}
