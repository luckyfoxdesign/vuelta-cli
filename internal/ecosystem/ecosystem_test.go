package ecosystem

import (
	"errors"
	"reflect"
	"testing"
)

type testAdapter struct {
	key      Key
	metadata Metadata
}

func (a testAdapter) Key() Key           { return a.key }
func (a testAdapter) Metadata() Metadata { return a.metadata }

func TestRegistryRejectsInvalidAndDuplicateKeys(t *testing.T) {
	t.Parallel()
	valid := testAdapter{key: Key{Stack: "example", PackageManager: "manager"}, metadata: Metadata{Version: "1"}}
	if _, err := NewRegistry(valid, valid); err == nil {
		t.Fatal("duplicate adapter was accepted")
	}
	invalid := testAdapter{key: Key{Stack: "", PackageManager: "manager"}, metadata: Metadata{Version: "1"}}
	if _, err := NewRegistry(invalid); err == nil {
		t.Fatal("invalid adapter key was accepted")
	}
}

func TestRegistryOrderingAndUnsupportedError(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(
		testAdapter{key: Key{Stack: "z", PackageManager: "b"}, metadata: Metadata{Version: "1"}},
		testAdapter{key: Key{Stack: "a", PackageManager: "c"}, metadata: Metadata{Version: "1"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{registry.Adapters()[0].Key().String(), registry.Adapters()[1].Key().String()}
	if want := []string{"a/c", "z/b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if _, err := registry.Lookup("missing", "manager"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("lookup error = %v", err)
	}
}
