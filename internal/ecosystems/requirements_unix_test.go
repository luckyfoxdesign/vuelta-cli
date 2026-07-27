//go:build unix

package ecosystems

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func TestRequirementsInputContractRejectsSelectedFIFO(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePipToolsFixture(t, root, "requirements.txt", "-r generated.txt\n")
	if err := syscall.Mkfifo(filepath.Join(root, "generated.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("PackageInputForRoot() error = %v", err)
	}
}
