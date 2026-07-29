package ecosystems

import (
	"errors"
	"fmt"
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

func TestRequirementsConstraintsUseOptionalProjectMetadataWithoutWideningScanInput(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePipToolsFixture(t, root, pipToolsCompiledFile, "demo==1.0.0\n")
	writePipToolsFixture(t, root, pipToolsMetadataFile, "[project]\nrequires-python = \"==3.14.*\"\n")

	adapter := Requirements()
	constraints, err := adapter.(ecosystem.ConstraintDetector).DetectConstraints(root, "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if constraints.Runtime != "==3.14.*" ||
		constraints.RuntimeConstraintSource != ecosystem.RuntimeConstraintSourceProject ||
		constraints.LockFormat != "requirements-direct" {
		t.Fatalf("constraints = %#v", constraints)
	}
	spec, err := adapter.(ecosystem.ToolchainProvider).DefaultToolchain(constraints)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Runtime != "3.14" {
		t.Fatalf("selected runtime = %q, want 3.14", spec.Runtime)
	}

	input, err := adapter.(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Files) != 1 || input.Files[0].Path != pipToolsCompiledFile {
		t.Fatalf("requirements scan input was widened: %#v", input.Files)
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

func TestRequirementsInputContractResolvesBoundedGraphDeterministically(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePipToolsFixture(t, root, "requirements.txt",
		"-r requirements/base.txt\n-c constraints/common.txt\n-r requirements/base.txt\nroot==1.0\n")
	writePipToolsFixture(t, root, "requirements/base.txt", "-r ../requirements.txt\nnested==2.0\n")
	writePipToolsFixture(t, root, "constraints/common.txt", "nested<3\n")

	provider := Requirements().(ecosystem.RootInputProvider)
	for _, resolve := range []func(string) (ecosystem.InputContract, error){
		func(root string) (ecosystem.InputContract, error) {
			return provider.PackageInputForRoot(root, false)
		},
		provider.DependencyInputForRoot,
	} {
		contract, err := resolve(root)
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, file := range contract.Files {
			paths = append(paths, file.Path)
			if file.Category != ecosystem.InputCategoryDependency {
				t.Fatalf("input category = %q", file.Category)
			}
		}
		want := []string{"constraints/common.txt", "requirements.txt", "requirements/base.txt"}
		if !reflect.DeepEqual(paths, want) {
			t.Fatalf("contract paths = %v, want %v", paths, want)
		}
	}
}

func TestRequirementsInputContractLeavesMissingIncludeAsEntryDiagnostic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePipToolsFixture(t, root, "requirements.txt", "-r missing.txt\nroot==1.0\n")
	contract, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(contract.Files) != 1 || contract.Files[0].Path != "requirements.txt" {
		t.Fatalf("contract = %#v", contract)
	}
}

func TestRequirementsInputContractRejectsUnsafeGraphEdges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, directive, want string
		setup                 func(*testing.T, string)
	}{
		{name: "traversal", directive: "-r ../outside.txt\n", want: "escapes the selected project"},
		{name: "absolute", directive: "-r /tmp/outside.txt\n", want: "project-relative"},
		{
			name: "symlink", directive: "-r nested.txt\n", want: "symbolic link",
			setup: func(t *testing.T, root string) {
				writePipToolsFixture(t, root, "target.txt", "demo==1.0\n")
				if err := os.Symlink("target.txt", filepath.Join(root, "nested.txt")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "special file", directive: "-r nested\n", want: "regular file",
			setup: func(t *testing.T, root string) {
				if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writePipToolsFixture(t, root, "requirements.txt", testCase.directive)
			if testCase.setup != nil {
				testCase.setup(t, root)
			}
			_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("PackageInputForRoot() error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestRequirementsInputContractEnforcesEveryGraphLimit(t *testing.T) {
	t.Parallel()
	t.Run("per-file bytes", func(t *testing.T) {
		root := t.TempDir()
		writePipToolsFixture(t, root, "requirements.txt",
			strings.Repeat("#", int(ecosystem.DefaultManifestLimit)+1))
		_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "no larger than") {
			t.Fatalf("per-file size error = %v", err)
		}
	})
	t.Run("record count", func(t *testing.T) {
		root := t.TempDir()
		writePipToolsFixture(t, root, "requirements.txt",
			strings.Repeat("#\n", maxRequirementRecords+1))
		_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "record count") {
			t.Fatalf("record count error = %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		for depth := 0; depth <= maxRequirementsDepth; depth++ {
			name := "requirements.txt"
			if depth > 0 {
				name = fmt.Sprintf("level-%d.txt", depth)
			}
			next := fmt.Sprintf("level-%d.txt", depth+1)
			writePipToolsFixture(t, root, name, "-r "+next+"\n")
		}
		_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "maximum depth") {
			t.Fatalf("depth error = %v", err)
		}
	})
	t.Run("file count", func(t *testing.T) {
		root := t.TempDir()
		var directives strings.Builder
		for index := 0; index < maxRequirementsFiles; index++ {
			name := fmt.Sprintf("part-%02d.txt", index)
			directives.WriteString("-r " + name + "\n")
			writePipToolsFixture(t, root, name, "# fixture\n")
		}
		writePipToolsFixture(t, root, "requirements.txt", directives.String())
		_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "file count") {
			t.Fatalf("file count error = %v", err)
		}
	})
	t.Run("aggregate bytes", func(t *testing.T) {
		root := t.TempDir()
		var directives strings.Builder
		for index := 0; index < 8; index++ {
			name := fmt.Sprintf("large-%02d.txt", index)
			directives.WriteString("-r " + name + "\n")
			writePipToolsFixture(t, root, name, strings.Repeat("#", int(ecosystem.DefaultManifestLimit)))
		}
		writePipToolsFixture(t, root, "requirements.txt", directives.String())
		_, err := Requirements().(ecosystem.RootInputProvider).PackageInputForRoot(root, false)
		if err == nil || !strings.Contains(err.Error(), "aggregate size") {
			t.Fatalf("aggregate size error = %v", err)
		}
	})
}

func TestPipToolsDecoderPreservesDiagnosticsAndCandidates(t *testing.T) {
	t.Parallel()
	report, err := PipTools().(ecosystem.CandidateDecoder).DecodeCandidates(
		[]byte(`{"candidates":[{"name":"demo","current":"1.0.0","latest_version":"2.0.0","file":"requirements/base.in","line":3,"disposition":"scanned"}],"diagnostics":[{"file":"requirements/base.in","line":2,"code":"exact_pin_required","severity":"info","disposition":"unsupported","message":"expected one exact pin"}]}`),
		map[string][]byte{
			pipToolsSourceFile:     []byte("-r requirements/base.in\n"),
			pipToolsCompiledFile:   []byte("demo==1.0.0\n"),
			"requirements/base.in": []byte("range>=1\ndemo==1.0.0\n"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 1 || len(report.Diagnostics) != 1 ||
		report.Candidates[0].File != "requirements/base.in" || report.Candidates[0].Line != 3 ||
		report.Candidates[0].Disposition != "scanned" ||
		report.Diagnostics[0].File != "requirements/base.in" ||
		report.Diagnostics[0].Disposition != "unsupported" {
		t.Fatalf("report = %#v", report)
	}
}

func TestRequirementsDecoderRejectsUnadmittedProvenance(t *testing.T) {
	t.Parallel()
	outputs := []string{
		`{"candidates":[{"name":"demo","current":"1.0","latest_version":"2.0","file":"../requirements.txt","line":1,"disposition":"scanned"}],"diagnostics":[]}`,
		`{"candidates":[{"name":"demo","current":"1.0","latest_version":"2.0","file":7,"line":"one","disposition":true}],"diagnostics":[]}`,
	}
	for _, output := range outputs {
		_, err := Requirements().(ecosystem.CandidateDecoder).DecodeCandidates(
			[]byte(output),
			map[string][]byte{"requirements.txt": []byte("demo==1.0\n")},
		)
		if err == nil || !strings.Contains(err.Error(), "provenance") {
			t.Fatalf("DecodeCandidates() error = %v", err)
		}
	}
}

func stringPointer(value string) *string {
	return &value
}
