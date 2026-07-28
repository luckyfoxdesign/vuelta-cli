package runlease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
)

const (
	OwnerLabel      = "com.luckyfoxdesign.vuelta.owner"
	ContractLabel   = "com.luckyfoxdesign.vuelta.lifecycle-contract"
	InvocationLabel = "com.luckyfoxdesign.vuelta.invocation"
	ResourceLabel   = "com.luckyfoxdesign.vuelta.resource"

	ContractValue = "1"

	OwnerScanner       = "scanner"
	OwnerManagedEgress = "managed-egress"

	ResourceScannerInput  = "scanner-input"
	ResourceScannerFinal  = "scanner-final"
	ResourceScannerDB     = "scanner-db-init"
	ResourceEgressProxy   = "managed-egress-proxy"
	ResourceEgressNetwork = "managed-egress-network"
)

var invocationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type contextKey struct{}

// NewID creates an opaque invocation identifier suitable for a Docker label.
func NewID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("generate Docker resource invocation identity")
	}
	return hex.EncodeToString(random), nil
}

// ValidID reports whether value is an exact Vuelta invocation identifier.
func ValidID(value string) bool {
	return invocationIDPattern.MatchString(value)
}

// WithInvocation attaches one validated invocation identity to ctx.
func WithInvocation(ctx context.Context, invocation string) (context.Context, error) {
	if !ValidID(invocation) {
		return nil, errors.New("invalid Docker resource invocation identity")
	}
	return context.WithValue(ctx, contextKey{}, invocation), nil
}

// WithoutInvocation prevents downstream persistent-resource creation from
// inheriting an invocation lease while preserving cancellation and deadlines.
func WithoutInvocation(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, "")
}

// Invocation returns the validated invocation identity attached to ctx.
func Invocation(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{}).(string)
	if !ValidID(value) {
		return ""
	}
	return value
}

// AppendLabelArgs appends the exact lifecycle labels used by cleanup.
func AppendLabelArgs(args []string, owner, resource, invocation string) []string {
	labels := Labels(owner, resource, invocation)
	if len(labels) == 0 {
		return args
	}
	for _, label := range labels {
		args = append(args, "--label", label)
	}
	return args
}

// AppendLifecycleLabelArgs adds the cleanup labels when the caller already
// supplies the shared ownership label for another identity contract.
func AppendLifecycleLabelArgs(args []string, resource, invocation string) []string {
	if !ValidID(invocation) {
		return args
	}
	return append(args,
		"--label", ContractLabel+"="+ContractValue,
		"--label", InvocationLabel+"="+invocation,
		"--label", ResourceLabel+"="+resource,
	)
}

// Labels returns the complete exact cleanup label set.
func Labels(owner, resource, invocation string) []string {
	if !ValidID(invocation) {
		return nil
	}
	return []string{
		OwnerLabel + "=" + owner,
		ContractLabel + "=" + ContractValue,
		InvocationLabel + "=" + invocation,
		ResourceLabel + "=" + resource,
	}
}
