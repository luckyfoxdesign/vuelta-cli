package projectstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReportCreatesPrivateProjectLocalState(t *testing.T) {
	root := t.TempDir()
	target, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.WriteReport([]byte("# report\n")); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{
		target.StateDir():   0o700,
		target.ReportPath(): 0o600,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), mode)
		}
	}
	data, err := os.ReadFile(target.ReportPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "# report\n" {
		t.Fatalf("report = %q", data)
	}
}

func TestProjectStateRejectsSymlinkAndPermissiveState(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, StateDirectoryName)); err != nil {
			t.Fatal(err)
		}
		target, err := Resolve(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := target.WriteReport([]byte("report")); err == nil {
			t.Fatal("symlinked state directory was accepted")
		}
	})
	t.Run("permissions", func(t *testing.T) {
		root := t.TempDir()
		state := filepath.Join(root, StateDirectoryName)
		if err := os.Mkdir(state, 0o755); err != nil {
			t.Fatal(err)
		}
		target, err := Resolve(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := target.WriteReport([]byte("report")); err == nil {
			t.Fatal("permissive state directory was accepted")
		}
	})
}

func TestWriteReportRejectsOversizedAndSymlinkDestination(t *testing.T) {
	root := t.TempDir()
	target, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.WriteReport(make([]byte, MaxReportBytes+1)); err == nil {
		t.Fatal("oversized report was accepted")
	}
	if err := target.EnsureState(); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target.ReportPath()); err != nil {
		t.Fatal(err)
	}
	if err := target.WriteReport([]byte("replace")); err == nil {
		t.Fatal("symlink report destination was accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatal("symlink target was modified")
	}
}
