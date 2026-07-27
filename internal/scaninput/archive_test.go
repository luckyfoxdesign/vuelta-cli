package scaninput

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	return dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func write(t *testing.T, root, relative, value string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, root string) {
	t.Helper()
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-q", "-m", "fixture")
}

func npmWorkspace(root string) config.Workspace {
	return config.Workspace{Path: root, Stack: config.StackNode, PackageManager: "npm"}
}

func archiveFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	result := make(map[string]string)
	r := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		contents, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		result[header.Name] = string(contents)
	}
	return result
}

func TestBuildArchivesOnlyAllowlistedTrackedInputs(t *testing.T) {
	root := initRepo(t)
	write(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	write(t, root, ".env.production", "sentinel")
	write(t, root, "credentials.json", "sentinel")
	write(t, root, "src/main.js", "sentinel")
	commitAll(t, root)
	if err := os.Symlink("package.json", filepath.Join(root, "manifest-link")); err != nil {
		t.Fatal(err)
	}

	contract, err := PackageContract(npmWorkspace(root), false)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
	if err != nil {
		t.Fatal(err)
	}
	files := archiveFiles(t, bundle.Archive)
	want := map[string]string{
		"project/package.json":      `{"dependencies":{"example":"1.0.0"}}`,
		"project/package-lock.json": `{"lockfileVersion":3}`,
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("archive file names = %v, want only package manifest and lock", sortedKeys(files))
	}
	if len(bundle.Manifest.InputHashes) != 2 || len(bundle.Manifest.Entries) != 2 {
		t.Fatalf("manifest = %#v", bundle.Manifest)
	}
}

func TestNPMManifestOnlyArchiveIsMinimalAndLockSelectionIsExact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, lock string
	}{
		{name: "manifest only"},
		{name: "package lock", lock: "package-lock.json"},
		{name: "shrinkwrap", lock: "npm-shrinkwrap.json"},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			write(t, root, "package.json", `{"name":"demo"}`)
			write(t, root, "unrelated-source.js", "sentinel")
			if testCase.lock != "" {
				write(t, root, testCase.lock, `{"lockfileVersion":3}`)
			}
			contract, err := PackageContract(npmWorkspace(root), false)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := Build(context.Background(), root, root, Options{}, contract)
			if err != nil {
				t.Fatal(err)
			}
			files := archiveFiles(t, bundle.Archive)
			if _, ok := files["project/package.json"]; !ok {
				t.Fatalf("archive = %#v", files)
			}
			if _, ok := files["project/unrelated-source.js"]; ok || len(files) != 1+boolInt(testCase.lock != "") {
				t.Fatalf("archive = %#v", files)
			}
			if testCase.lock != "" {
				if _, ok := files["project/"+testCase.lock]; !ok {
					t.Fatalf("archive omitted %s: %#v", testCase.lock, files)
				}
			}
		})
	}
}

func TestNPMContractRejectsAmbiguousLocks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, "package.json", `{"name":"demo"}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)
	write(t, root, "npm-shrinkwrap.json", `{"lockfileVersion":3}`)
	if _, err := PackageContract(npmWorkspace(root), false); err == nil || !strings.Contains(err.Error(), "both package-lock.json") {
		t.Fatalf("PackageContract() error = %v", err)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestPythonRequirementsContractIsManagerIndependentAndMinimal(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "-r requirements/base.txt\n-c constraints.txt\nflask==0.5\n")
	write(t, root, "requirements/base.txt", "requests==2.31.0\n")
	write(t, root, "constraints.txt", "requests<3\n")
	write(t, root, "requirements.in", "flask\n")
	write(t, root, "pyproject.toml", "[project]\nname = \"unrelated\"\n")

	contract, err := DependencyContract(config.Workspace{Path: root, Stack: config.StackPython})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(context.Background(), root, root, Options{}, contract)
	if err != nil {
		t.Fatal(err)
	}
	files := archiveFiles(t, bundle.Archive)
	want := map[string]string{
		"project/requirements.txt":      "-r requirements/base.txt\n-c constraints.txt\nflask==0.5\n",
		"project/requirements/base.txt": "requests==2.31.0\n",
		"project/constraints.txt":       "requests<3\n",
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("archive files = %v, want only standalone requirements graph", sortedKeys(files))
	}
	if len(bundle.Manifest.Entries) != len(want) {
		t.Fatalf("manifest = %#v", bundle.Manifest)
	}
	for _, entry := range bundle.Manifest.Entries {
		if entry.Category != CategoryDependency {
			t.Fatalf("manifest entry = %#v", entry)
		}
	}
	if _, err := PackageContract(config.Workspace{Path: root, Stack: config.StackPython}, false); err == nil {
		t.Fatal("standalone requirements.txt unexpectedly enabled a package contract")
	}
	packageContract, err := PackageContract(config.Workspace{Path: root, Stack: config.StackPython, PackageManager: "requirements"}, false)
	if err != nil {
		t.Fatal(err)
	}
	packageBundle, err := Build(context.Background(), root, root, Options{}, packageContract)
	if err != nil {
		t.Fatal(err)
	}
	if got := archiveFiles(t, packageBundle.Archive); !reflect.DeepEqual(got, want) {
		t.Fatalf("package archive files = %v, want only requirements graph", sortedKeys(got))
	}
}

func TestPipToolsContractArchivesOnlyTheExplicitRequirementsGraph(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, "requirements.in", "-r requirements/base.in\n-c constraints.txt\ndemo\n")
	write(t, root, "requirements.txt", "demo==1.0.0 \\\n    --hash=sha256:abc\n")
	write(t, root, "requirements/base.in", "base\n")
	write(t, root, "constraints.txt", "shared==2.0.0\n")
	write(t, root, "pyproject.toml", "[project]\nrequires-python = \">=3.11\"\n")
	write(t, root, "src/unrelated.py", "sentinel\n")

	contract, err := PackageContract(config.Workspace{
		Path: root, Stack: config.StackPython, PackageManager: "pip-tools",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(context.Background(), root, root, Options{}, contract)
	if err != nil {
		t.Fatal(err)
	}
	files := archiveFiles(t, bundle.Archive)
	want := map[string]string{
		"project/requirements.in":      "-r requirements/base.in\n-c constraints.txt\ndemo\n",
		"project/requirements.txt":     "demo==1.0.0 \\\n    --hash=sha256:abc\n",
		"project/requirements/base.in": "base\n",
		"project/constraints.txt":      "shared==2.0.0\n",
		"project/pyproject.toml":       "[project]\nrequires-python = \">=3.11\"\n",
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("archive files = %v, want %v", sortedKeys(files), sortedKeys(want))
	}
}

func TestPipToolsCorpusLayoutsResolveWithoutPyproject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		compiled string
		extra    map[string]string
	}{
		{
			name:     "gcpdiag hashes",
			source:   "google-cloud-core\n",
			compiled: "google-cloud-core==2.4.1 \\\n    --hash=sha256:abc\n",
		},
		{
			name:     "AWS CDK constraint",
			source:   "-c constraints.txt\naws-cdk-lib\n",
			compiled: "aws-cdk-lib==2.100.0\n",
			extra:    map[string]string{"constraints.txt": "constructs==10.3.0\n"},
		},
		{
			name:     "Dallinger nested source",
			source:   "-r requirements/base.in\ndallinger\n",
			compiled: "dallinger==11.0.0\n",
			extra:    map[string]string{"requirements/base.in": "requests\n"},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			write(t, root, "requirements.in", testCase.source)
			write(t, root, "requirements.txt", testCase.compiled)
			for name, contents := range testCase.extra {
				write(t, root, name, contents)
			}
			contract, err := PackageContract(config.Workspace{
				Path: root, Stack: config.StackPython, PackageManager: "pip-tools",
			}, false)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := Build(context.Background(), root, root, Options{}, contract)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := bundle.Content("pyproject.toml"); ok {
				t.Fatal("absent optional pyproject.toml was synthesized")
			}
			if len(bundle.Manifest.Entries) != 2+len(testCase.extra) {
				t.Fatalf("manifest entries = %#v", bundle.Manifest.Entries)
			}
		})
	}
}

func TestPythonRequirementsContractRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T, string)
		limits Limits
		want   string
	}{
		{name: "symlink", setup: func(t *testing.T, root string) {
			outside := filepath.Join(t.TempDir(), "outside.txt")
			if err := os.WriteFile(outside, []byte("flask==0.5\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "requirements.txt")); err != nil {
				t.Fatal(err)
			}
		}, want: "regular file"},
		{name: "hardlink", setup: func(t *testing.T, root string) {
			write(t, root, "outside.txt", "flask==0.5\n")
			if err := os.Link(filepath.Join(root, "outside.txt"), filepath.Join(root, "requirements.txt")); err != nil {
				t.Fatal(err)
			}
		}, want: "hard links"},
		{name: "oversized", setup: func(t *testing.T, root string) {
			write(t, root, "requirements.txt", "flask==0.5\n")
		}, limits: Limits{MaxFileBytes: 4}, want: "size limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.setup(t, root)
			_, err := Build(context.Background(), root, root, Options{Limits: test.limits}, PythonRequirementsContract())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPythonRequirementsContractRejectsChangedDuringRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 16<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	started := make(chan struct{})
	go func() {
		close(started)
		for tick := int64(1); ; tick++ {
			select {
			case <-stop:
				return
			default:
				stamp := time.Unix(1_700_000_000, tick)
				_ = os.Chtimes(path, stamp, stamp)
			}
		}
	}()
	<-started
	_, err := Build(context.Background(), root, root, Options{Limits: Limits{
		MaxFileBytes: 32 << 20, MaxTotalBytes: 32 << 20,
	}}, PythonRequirementsContract())
	close(stop)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("Build error = %v, want changed-during-read rejection", err)
	}
}

func TestBuildRejectsSecretLikeBroadAllowlistWithoutDisclosingPath(t *testing.T) {
	root := initRepo(t)
	write(t, root, ".env.production", "sentinel")
	commitAll(t, root)
	contract := Contract{Stage: StageDockerManifest, Files: []File{{Path: ".env.production", Category: CategoryDockerManifest}}}
	_, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
	if err == nil || !strings.Contains(err.Error(), "secret-like") {
		t.Fatalf("expected secret-like input rejection, got %v", err)
	}
	if strings.Contains(err.Error(), ".env") || strings.Contains(err.Error(), "production") {
		t.Fatalf("error disclosed secret-like path: %v", err)
	}
}

func TestBuildRejectsUntrackedIgnoredSymlinkAndHardlink(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
		want  string
	}{
		{"untracked", func(t *testing.T, root string) { write(t, root, "Dockerfile", "FROM scratch") }, "tracked"},
		{"ignored", func(t *testing.T, root string) {
			write(t, root, ".gitignore", "Dockerfile\n")
			write(t, root, "Dockerfile", "FROM scratch")
			runGit(t, root, "add", ".gitignore")
			runGit(t, root, "add", "-f", "Dockerfile")
			runGit(t, root, "commit", "-q", "-m", "fixture")
		}, "ignored"},
		{"symlink", func(t *testing.T, root string) {
			write(t, root, "target", "FROM scratch")
			if err := os.Symlink("target", filepath.Join(root, "Dockerfile")); err != nil {
				t.Fatal(err)
			}
			commitAll(t, root)
		}, "regular"},
		{"hardlink", func(t *testing.T, root string) {
			write(t, root, "Dockerfile", "FROM scratch")
			if err := os.Link(filepath.Join(root, "Dockerfile"), filepath.Join(root, "alias")); err != nil {
				t.Fatal(err)
			}
			commitAll(t, root)
		}, "hard links"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := initRepo(t)
			test.setup(t, root)
			contract := Contract{Stage: StageDockerManifest, Files: []File{{Path: "Dockerfile", Category: CategoryDockerManifest}}}
			_, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestReviewedManagerConfigIsOptInAndRejectsCredentials(t *testing.T) {
	root := initRepo(t)
	write(t, root, "package.json", `{}`)
	write(t, root, "package-lock.json", `{}`)
	write(t, root, ".npmrc", "registry=https://registry.npmjs.org/\nstrict-ssl=true\n")
	commitAll(t, root)

	withoutConfig, err := PackageContract(npmWorkspace(root), false)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(context.Background(), root, root, Options{RequireTracked: true}, withoutConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle.Content(".npmrc"); ok {
		t.Fatal("manager config was included without opt-in")
	}
	if containsString(ManifestCategories(bundle.Manifest), string(CategoryManagerConfig)) {
		t.Fatal("absent manager config category was reported")
	}

	withConfig, err := PackageContract(npmWorkspace(root), true)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = Build(context.Background(), root, root, Options{RequireTracked: true}, withConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle.Content(".npmrc"); !ok {
		t.Fatal("reviewed safe manager config was not included")
	}
	if !containsString(ManifestCategories(bundle.Manifest), string(CategoryManagerConfig)) {
		t.Fatal("included manager config category was not reported")
	}

	write(t, root, ".npmrc", "//registry.npmjs.org/:_authToken=REDACTED_SENTINEL\n")
	_, err = Build(context.Background(), root, root, Options{RequireTracked: true}, withConfig)
	if err == nil || !strings.Contains(err.Error(), "credential-bearing") {
		t.Fatalf("expected credential-bearing config rejection, got %v", err)
	}
	if strings.Contains(err.Error(), ".npmrc") || strings.Contains(err.Error(), "REDACTED") {
		t.Fatalf("manager config error disclosed a path or value: %v", err)
	}
}

func TestManifestChangesOnlyForContractInputs(t *testing.T) {
	root := initRepo(t)
	write(t, root, "package.json", `{}`)
	write(t, root, "package-lock.json", `{"version":1}`)
	write(t, root, "src/main.js", "one")
	commitAll(t, root)
	contract, err := PackageContract(npmWorkspace(root), false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "src/main.js", "two")
	second, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.Hash != second.Manifest.Hash {
		t.Fatal("unrelated source changed the scan input identity")
	}
	write(t, root, "package-lock.json", `{"version":2}`)
	third, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.Hash == third.Manifest.Hash {
		t.Fatal("lockfile change did not invalidate the scan input identity")
	}
}

func TestBuildFailsClosedOnLimitsAndCancellation(t *testing.T) {
	root := initRepo(t)
	write(t, root, "package.json", `{}`)
	write(t, root, "package-lock.json", `{"large":true}`)
	commitAll(t, root)
	contract, err := PackageContract(npmWorkspace(root), false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build(context.Background(), root, root, Options{RequireTracked: true, Limits: Limits{MaxFileBytes: 4}}, contract)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected input limit error, got %v", err)
	}
	_, err = Build(context.Background(), root, root, Options{RequireTracked: true, Limits: Limits{MaxTotalBytes: 5}}, contract)
	if err == nil || !strings.Contains(err.Error(), "total size limit") {
		t.Fatalf("expected total input limit error, got %v", err)
	}
	many := Contract{Stage: StageDockerManifest, Files: []File{
		{Path: "one", Category: CategoryDockerManifest},
		{Path: "two", Category: CategoryDockerManifest},
	}}
	_, err = Build(context.Background(), root, root, Options{Limits: Limits{MaxFiles: 1}}, many)
	if err == nil || !strings.Contains(err.Error(), "count exceeds") {
		t.Fatalf("expected input count limit error, got %v", err)
	}
	deep := Contract{Stage: StageDockerManifest, Files: []File{{Path: "one/two/Dockerfile", Category: CategoryDockerManifest}}}
	_, err = Build(context.Background(), root, root, Options{Limits: Limits{MaxDepth: 2}}, deep)
	if err == nil || !strings.Contains(err.Error(), "depth exceeds") {
		t.Fatalf("expected input depth limit error, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Build(ctx, root, root, Options{RequireTracked: true}, contract)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestMaterializePrivateUsesOwnerOnlyPermissionsAndCleansUp(t *testing.T) {
	root := initRepo(t)
	write(t, root, "package.json", `{}`)
	write(t, root, "package-lock.json", `{}`)
	commitAll(t, root)
	contract, err := PackageContract(npmWorkspace(root), false)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(context.Background(), root, root, Options{RequireTracked: true}, contract)
	if err != nil {
		t.Fatal(err)
	}
	private, err := MaterializePrivate(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	dir := private.Dir
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("private directory mode = %v", info.Mode().Perm())
	}
	fileInfo, err := os.Stat(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private file mode = %v", fileInfo.Mode().Perm())
	}
	if err := private.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private context remains after Close: %v", err)
	}
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
