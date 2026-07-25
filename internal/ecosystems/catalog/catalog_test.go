package catalog

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestBuiltinsAreDeterministicAndCapabilityBounded(t *testing.T) {
	t.Parallel()
	first, err := New()
	if err != nil {
		t.Fatal(err)
	}
	second, err := New()
	if err != nil {
		t.Fatal(err)
	}
	keys := func(registry *ecosystem.Registry) []string {
		adapters := registry.Adapters()
		result := make([]string, len(adapters))
		for index, adapter := range adapters {
			result[index] = adapter.Key().String()
		}
		return result
	}
	if !reflect.DeepEqual(keys(first), keys(second)) {
		t.Fatalf("catalog order changed: %v != %v", keys(first), keys(second))
	}
	requirements, err := first.Lookup("python", "requirements")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := requirements.(ecosystem.MutationProvider); ok {
		t.Fatal("python/requirements unexpectedly exposes mutation")
	}
	bun, err := first.Lookup("node", "bun")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bun.(ecosystem.ScannerProvider); ok {
		t.Fatal("node/bun unexpectedly exposes candidate scanning")
	}
}

func TestDiscoverUsesRequirementsOnlyAsPythonFallback(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt")
	adapters, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 1 || adapters[0].Key().String() != "python/requirements" {
		t.Fatalf("requirements fallback = %#v", adapters)
	}
	write("requirements.in")
	adapters, err = Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 1 || adapters[0].Key().String() != "python/pip-tools" {
		t.Fatalf("pip-tools detection = %#v", adapters)
	}
}
