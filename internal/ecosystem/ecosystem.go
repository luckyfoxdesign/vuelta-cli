// Package ecosystem defines the stable, data-only boundary between Vuelta's
// orchestration and built-in package ecosystem adapters.
//
// Adapters describe reviewed files, toolchains, scanner argv, decoders, and
// mutation policy. They never execute commands, access Docker, Git, credentials,
// or the host worktree outside the exact root passed by core.
package ecosystem

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var keyPartPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

var (
	// ErrUnsupported marks an unknown stack/package-manager pair.
	ErrUnsupported = errors.New("unsupported ecosystem")
	// ErrCapabilityUnavailable marks a known adapter without a requested
	// capability.
	ErrCapabilityUnavailable = errors.New("ecosystem capability unavailable")
	// ErrScanOnly marks a mutation request for a read-only adapter.
	ErrScanOnly = errors.New("scan-only ecosystem")
)

// Key identifies one independently registered stack/package-manager pair.
type Key struct {
	Stack          string `json:"stack"`
	PackageManager string `json:"package_manager"`
}

// NewKey validates and returns an adapter key.
func NewKey(stack, packageManager string) (Key, error) {
	key := Key{Stack: stack, PackageManager: packageManager}
	if err := key.Validate(); err != nil {
		return Key{}, err
	}
	return key, nil
}

// Validate rejects empty or non-canonical adapter identities.
func (k Key) Validate() error {
	if !keyPartPattern.MatchString(k.Stack) || !keyPartPattern.MatchString(k.PackageManager) {
		return fmt.Errorf("invalid ecosystem key %q/%q", k.Stack, k.PackageManager)
	}
	return nil
}

// String returns the stable persisted adapter ID.
func (k Key) String() string {
	return k.Stack + "/" + k.PackageManager
}

// Metadata is immutable descriptive and lifecycle information for an adapter.
type Metadata struct {
	DisplayName       string
	Version           string
	DetectionPriority int
	FallbackDetection bool
	UnsupportedReason string
}

// Adapter is the small identity interface implemented by every built-in pair.
type Adapter interface {
	Key() Key
	Metadata() Metadata
}

// UnsupportedError identifies an unknown adapter key.
type UnsupportedError struct {
	Key Key
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("%s: %s", ErrUnsupported, e.Key.String())
}

// Unwrap supports errors.Is(err, ErrUnsupported).
func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

// CapabilityError identifies a known adapter that deliberately lacks a
// capability.
type CapabilityError struct {
	Key        Key
	Capability string
	ScanOnly   bool
	Reason     string
}

func (e *CapabilityError) Error() string {
	base := ErrCapabilityUnavailable
	if e.ScanOnly {
		base = ErrScanOnly
	}
	if e.Reason != "" {
		return fmt.Sprintf("%s: %s capability %q: %s", base, e.Key.String(), e.Capability, e.Reason)
	}
	return fmt.Sprintf("%s: %s capability %q", base, e.Key.String(), e.Capability)
}

// Unwrap supports errors.Is for capability and scan-only failures.
func (e *CapabilityError) Unwrap() error {
	if e.ScanOnly {
		return ErrScanOnly
	}
	return ErrCapabilityUnavailable
}

// Registry is an immutable, deterministic adapter catalog.
type Registry struct {
	ordered []Adapter
	byKey   map[string]Adapter
}

// NewRegistry validates all adapters, rejects duplicates, and stores them in
// stable key order.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	byKey := make(map[string]Adapter, len(adapters))
	for index, adapter := range adapters {
		if adapter == nil {
			return nil, fmt.Errorf("ecosystem adapter %d is nil", index)
		}
		key := adapter.Key()
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("ecosystem adapter %d: %w", index, err)
		}
		if strings.TrimSpace(adapter.Metadata().Version) == "" {
			return nil, fmt.Errorf("ecosystem adapter %s has no version", key.String())
		}
		if _, exists := byKey[key.String()]; exists {
			return nil, fmt.Errorf("duplicate ecosystem adapter %s", key.String())
		}
		byKey[key.String()] = adapter
	}
	ordered := make([]Adapter, 0, len(byKey))
	for _, adapter := range byKey {
		ordered = append(ordered, adapter)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Key().String() < ordered[j].Key().String()
	})
	return &Registry{ordered: ordered, byKey: byKey}, nil
}

// Lookup returns one adapter or a typed unsupported error.
func (r *Registry) Lookup(stack, packageManager string) (Adapter, error) {
	key := Key{Stack: stack, PackageManager: packageManager}
	adapter, ok := r.byKey[key.String()]
	if !ok {
		return nil, &UnsupportedError{Key: key}
	}
	return adapter, nil
}

// Adapters returns a defensive copy in stable key order.
func (r *Registry) Adapters() []Adapter {
	return append([]Adapter(nil), r.ordered...)
}

// PackageManagers returns the registered managers for a stack in stable order.
func (r *Registry) PackageManagers(stack string) []string {
	var managers []string
	for _, adapter := range r.ordered {
		if adapter.Key().Stack == stack {
			managers = append(managers, adapter.Key().PackageManager)
		}
	}
	return managers
}

// Stacks returns registered stacks in stable order.
func (r *Registry) Stacks() []string {
	seen := make(map[string]bool)
	var stacks []string
	for _, adapter := range r.ordered {
		stack := adapter.Key().Stack
		if !seen[stack] {
			seen[stack] = true
			stacks = append(stacks, stack)
		}
	}
	return stacks
}
