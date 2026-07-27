package adhoc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func npmProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
	writeFile(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	return root
}

func TestDetectRejectsManifestSymlink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package-lock.json", "{}")
	if err := os.Symlink("package-lock.json", filepath.Join(root, "package.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(root); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("Detect error = %v, want rejected symlink", err)
	}
}

func TestDetectScanAcceptsManifestOnlyButUpdateDetectionDoesNot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"demo"}`)
	project, err := DetectScan(root)
	if err != nil {
		t.Fatal(err)
	}
	if project.Stack != "node" || project.Manager != "npm" || project.Manifest != "package.json" || project.Lock != "" {
		t.Fatalf("DetectScan() = %#v", project)
	}
	if _, err := Detect(root); err == nil || !strings.Contains(err.Error(), "manifest/lock pair") {
		t.Fatalf("Detect() error = %v", err)
	}
}

func TestDetectAcceptsNPMShrinkwrapAndRejectsAmbiguousLocks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"demo"}`)
	writeFile(t, root, "npm-shrinkwrap.json", `{"lockfileVersion":3}`)
	project, err := Detect(root)
	if err != nil || project.Lock != "npm-shrinkwrap.json" {
		t.Fatalf("Detect() = %#v, %v", project, err)
	}
	writeFile(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	if _, err := DetectScan(root); err == nil || !strings.Contains(err.Error(), "both package-lock.json") {
		t.Fatalf("DetectScan() ambiguous error = %v", err)
	}
}

func TestInPrivateCopyRejectsConfigMutation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", "{}")
	writeFile(t, root, "bun.lock", "lock")
	writeFile(t, root, "bunfig.toml", "telemetry = false")
	_, err := InPrivateCopy(root, true, true, func(project Project) error {
		writeFile(t, project.Root, "bunfig.toml", "telemetry = true")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "unallowlisted") {
		t.Fatalf("InPrivateCopy error = %v, want config mutation rejection", err)
	}
	data, readErr := os.ReadFile(filepath.Join(root, "bunfig.toml"))
	if readErr != nil || string(data) != "telemetry = false" {
		t.Fatalf("host config = %q, %v", data, readErr)
	}
}

func TestInPrivateCopyRefusesConcurrentHostChange(t *testing.T) {
	root := npmProject(t)
	changed, err := InPrivateCopy(root, false, true, func(project Project) error {
		writeFile(t, project.Root, "package.json", `{"dependencies":{"example":"2.0.0"}}`)
		writeFile(t, root, "package.json", `{"dependencies":{"external":"3.0.0"}}`)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed during private update") {
		t.Fatalf("InPrivateCopy changed=%v error=%v", changed, err)
	}
	host, readErr := os.ReadFile(filepath.Join(root, "package.json"))
	if readErr != nil || !strings.Contains(string(host), "external") {
		t.Fatalf("concurrent host change was overwritten: %q, %v", host, readErr)
	}
}
