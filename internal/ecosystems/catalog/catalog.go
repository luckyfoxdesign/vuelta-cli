// Package catalog explicitly constructs the immutable built-in adapter set.
// It deliberately has no init registration or filesystem discovery.
package catalog

import (
	"fmt"
	"sort"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems"
)

// New constructs the complete built-in adapter catalog.
func New() (*ecosystem.Registry, error) {
	return ecosystem.NewRegistry(
		ecosystems.NPM(),
		ecosystems.PNPM(),
		ecosystems.Bun(),
		ecosystems.Poetry(),
		ecosystems.UV(),
		ecosystems.PipTools(),
		ecosystems.Requirements(),
	)
}

// Discover runs only each adapter's bounded root detector. Fallback adapters
// are returned only when no non-fallback adapter for the same stack matched.
func Discover(root string) ([]ecosystem.Adapter, error) {
	registry, err := New()
	if err != nil {
		return nil, err
	}
	var primary []ecosystem.Adapter
	var fallback []ecosystem.Adapter
	matchedStacks := make(map[string]bool)
	for _, adapter := range registry.Adapters() {
		detector, ok := adapter.(ecosystem.Detector)
		if !ok {
			continue
		}
		matched, err := detector.Detect(root)
		if err != nil {
			return nil, fmt.Errorf("detect %s: %w", adapter.Key().String(), err)
		}
		if !matched {
			continue
		}
		if adapter.Metadata().FallbackDetection {
			fallback = append(fallback, adapter)
			continue
		}
		primary = append(primary, adapter)
		matchedStacks[adapter.Key().Stack] = true
	}
	for _, adapter := range fallback {
		if !matchedStacks[adapter.Key().Stack] {
			primary = append(primary, adapter)
		}
	}
	sort.Slice(primary, func(i, j int) bool {
		left, right := primary[i], primary[j]
		if left.Metadata().DetectionPriority != right.Metadata().DetectionPriority {
			return left.Metadata().DetectionPriority < right.Metadata().DetectionPriority
		}
		return left.Key().String() < right.Key().String()
	})
	return primary, nil
}
