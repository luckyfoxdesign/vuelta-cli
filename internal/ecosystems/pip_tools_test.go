package ecosystems

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

func writePipToolsFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPipToolsConstraintsTreatProjectMetadataAsOptional(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		metadata    *string
		wantRuntime string
		wantSource  string
		wantCode    string
	}{
		{name: "absent metadata", wantSource: ecosystem.RuntimeConstraintSourceDefault},
		{
			name:        "valid project metadata",
			metadata:    stringPointer("[project]\nrequires-python = \">=3.11,<3.13\"\n"),
			wantRuntime: ">=3.11,<3.13", wantSource: ecosystem.RuntimeConstraintSourceProject,
		},
		{
			name:       "metadata without runtime",
			metadata:   stringPointer("[project]\nname = \"demo\"\n"),
			wantSource: ecosystem.RuntimeConstraintSourceDefault,
		},
		{
			name:     "malformed selected runtime metadata",
			metadata: stringPointer("[project]\nrequires-python = [\">=3.11\"]\n"),
			wantCode: ecosystem.RuntimeConstraintInvalid,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writePipToolsFixture(t, root, pipToolsSourceFile, "demo\n")
			writePipToolsFixture(t, root, pipToolsCompiledFile, "demo==1.0.0\n")
			if testCase.metadata != nil {
				writePipToolsFixture(t, root, pipToolsMetadataFile, *testCase.metadata)
			}
			constraints, err := PipTools().(ecosystem.ConstraintDetector).
				DetectConstraints(root, "linux/amd64")
			if testCase.wantCode != "" {
				var constraintErr *ecosystem.RuntimeConstraintError
				if !errors.As(err, &constraintErr) ||
					constraintErr.ReasonCode != testCase.wantCode {
					t.Fatalf("DetectConstraints() error = %T %v", err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if constraints.Runtime != testCase.wantRuntime ||
				constraints.RuntimeConstraintSource != testCase.wantSource ||
				constraints.LockFormat != "requirements" {
				t.Fatalf("constraints = %#v", constraints)
			}
		})
	}
}

func TestPipToolsConstraintsRejectUnsafeSelectedMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePipToolsFixture(t, root, pipToolsSourceFile, "demo\n")
	writePipToolsFixture(t, root, pipToolsCompiledFile, "demo==1.0.0\n")
	writePipToolsFixture(t, root, "metadata.toml", "[project]\nrequires-python = \">=3.11\"\n")
	if err := os.Symlink("metadata.toml", filepath.Join(root, pipToolsMetadataFile)); err != nil {
		t.Fatal(err)
	}
	_, err := PipTools().(ecosystem.ConstraintDetector).DetectConstraints(root, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("DetectConstraints() error = %v", err)
	}
}

func TestPipToolsInputContractResolvesOnlyExplicitRequirementsGraph(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePipToolsFixture(t, root, pipToolsSourceFile,
		"-r requirements/base.in\n-c constraints/common.txt\ndemo\n")
	writePipToolsFixture(t, root, pipToolsCompiledFile,
		"demo==1.0.0 \\\n    --hash=sha256:abc\n-r generated/extra.txt\n")
	writePipToolsFixture(t, root, "requirements/base.in", "-c ../constraints/common.txt\nbase\n")
	writePipToolsFixture(t, root, "constraints/common.txt", "shared==2.0.0\n")
	writePipToolsFixture(t, root, "generated/extra.txt", "extra==3.0.0\n")
	writePipToolsFixture(t, root, "unrelated/source.py", "sentinel\n")

	contract, err := PipTools().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, file := range contract.Files {
		paths = append(paths, file.Path)
	}
	want := []string{
		pipToolsSourceFile,
		pipToolsCompiledFile,
		pipToolsMetadataFile,
		"constraints/common.txt",
		"generated/extra.txt",
		"requirements/base.in",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("contract paths = %v, want %v", paths, want)
	}
	if !contract.Files[2].Optional {
		t.Fatalf("pyproject input is not optional: %#v", contract.Files[2])
	}
}

func TestPipToolsInputContractRejectsTraversalAndSelectedSymlinks(t *testing.T) {
	t.Parallel()
	t.Run("traversal", func(t *testing.T) {
		root := t.TempDir()
		writePipToolsFixture(t, root, pipToolsSourceFile, "-r ../outside.txt\n")
		writePipToolsFixture(t, root, pipToolsCompiledFile, "demo==1.0.0\n")
		_, err := PipTools().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "escapes the selected project") {
			t.Fatalf("PackageInputForRoot() error = %v", err)
		}
	})
	t.Run("selected symlink", func(t *testing.T) {
		root := t.TempDir()
		writePipToolsFixture(t, root, pipToolsSourceFile, "-r nested.txt\n")
		writePipToolsFixture(t, root, pipToolsCompiledFile, "demo==1.0.0\n")
		writePipToolsFixture(t, root, "target.txt", "demo==1.0.0\n")
		if err := os.Symlink("target.txt", filepath.Join(root, "nested.txt")); err != nil {
			t.Fatal(err)
		}
		_, err := PipTools().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("PackageInputForRoot() error = %v", err)
		}
	})
	t.Run("secret-like name before filesystem access", func(t *testing.T) {
		root := t.TempDir()
		writePipToolsFixture(t, root, pipToolsSourceFile, "-r credentials.txt\n")
		writePipToolsFixture(t, root, pipToolsCompiledFile, "demo==1.0.0\n")
		_, err := PipTools().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "secret-like") ||
			strings.Contains(err.Error(), "credentials.txt") {
			t.Fatalf("PackageInputForRoot() error = %v", err)
		}
	})
}

func TestPipToolsDecoderPreservesDiagnosticsAndCandidates(t *testing.T) {
	t.Parallel()
	report, err := PipTools().(ecosystem.CandidateDecoder).DecodeCandidates(
		[]byte(`{"candidates":[{"name":"demo","current":"1.0.0","latest_version":"2.0.0"}],"diagnostics":[{"file":"requirements.in","line":2,"code":"exact_pin_required","severity":"info","message":"expected one exact pin"}]}`),
		map[string][]byte{
			pipToolsSourceFile:   []byte("demo\n"),
			pipToolsCompiledFile: []byte("demo==1.0.0\n"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 1 || len(report.Diagnostics) != 1 ||
		report.Diagnostics[0].File != pipToolsSourceFile {
		t.Fatalf("report = %#v", report)
	}
}

func stringPointer(value string) *string {
	return &value
}
