package ecosystems

import (
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestBunFixUsesNativeBunWithoutScripts(t *testing.T) {
	t.Parallel()
	provider := Bun().(ecosystem.FixProvider)
	spec, err := provider.Fix(ecosystem.FixRequest{Name: "lodash", Version: "4.17.21", Dependency: ecosystem.FixDependency{Direct: true}})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"bun", "install", "--lockfile-only", "--ignore-scripts"}}
	if !spec.RewriteJSON || spec.LockOnly || spec.Unsupported != "" || !reflect.DeepEqual(spec.Commands, want) {
		t.Fatalf("unexpected direct Bun repair: %+v", spec)
	}
	transitive, err := provider.Fix(ecosystem.FixRequest{Name: "lodash", Version: "4.17.21"})
	if err != nil || transitive.Unsupported != "needs_parent_upgrade" || len(transitive.Commands) != 0 {
		t.Fatalf("transitive Bun repair must need its parent: %+v, %v", transitive, err)
	}
	if _, err = provider.Fix(ecosystem.FixRequest{Name: "--evil", Version: "1.0.0"}); err == nil {
		t.Fatal("option-like package name was accepted")
	}
}

func TestBunFixToolchainIsPinnedRepairImage(t *testing.T) {
	t.Parallel()
	provider := Bun().(ecosystem.FixProvider)
	spec, err := provider.FixToolchain(ecosystem.Constraints{Key: Bun().Key(), PackageManagerVersion: "1.4.5", Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Dockerfile != "bun-fix.Dockerfile" || spec.BuildArgs["BASE_IMAGE"] != "oven/bun:1.4.5" || spec.Scanner != "bun" {
		t.Fatalf("unexpected Bun repair toolchain: %+v", spec)
	}
	for _, version := range []string{"latest", "1.4", "1.4.5-canary"} {
		if _, err = provider.FixToolchain(ecosystem.Constraints{Key: Bun().Key(), PackageManagerVersion: version}); err == nil || !strings.Contains(err.Error(), "exact stable") {
			t.Fatalf("version %q accepted: %v", version, err)
		}
	}
}

func TestBunStaysWithoutScannerAndMutation(t *testing.T) {
	t.Parallel()
	adapter := Bun()
	if _, ok := adapter.(ecosystem.ScannerProvider); ok {
		t.Fatal("Bun must not expose a candidate scanner")
	}
	if _, ok := adapter.(ecosystem.MutationProvider); ok {
		t.Fatal("Bun must not expose update mutation")
	}
}
