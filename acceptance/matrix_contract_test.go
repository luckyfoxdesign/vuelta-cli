package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"gopkg.in/yaml.v3"
)

func TestAdaptiveMatrixProfileExpectationsMatchEmbeddedResolver(t *testing.T) {
	data, err := os.ReadFile("matrix.example.yaml")
	if err != nil {
		t.Fatalf("read matrix: %v", err)
	}
	var matrix struct {
		Cases []struct {
			Name              string                   `yaml:"name"`
			FixtureRoot       string                   `yaml:"fixture_root"`
			Fixture           string                   `yaml:"fixture"`
			Stack             string                   `yaml:"stack"`
			PackageManager    string                   `yaml:"package_manager"`
			ExpectedProfileID string                   `yaml:"expected_profile_id"`
			Profile           *config.ToolchainProfile `yaml:"profile"`
		} `yaml:"cases"`
	}
	if err := yaml.Unmarshal(data, &matrix); err != nil {
		t.Fatalf("parse matrix: %v", err)
	}
	embeddedProfiles := make(map[string]bool, len(matrix.Cases))
	for _, testCase := range matrix.Cases {
		if testCase.Profile != nil {
			continue
		}
		embeddedProfiles[testCase.ExpectedProfileID] = true
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			root := filepath.Join("..", filepath.FromSlash(testCase.FixtureRoot), testCase.Fixture)
			selection, err := toolchain.Select(config.Workspace{
				Path: root, Stack: testCase.Stack, PackageManager: testCase.PackageManager,
				Platform: "linux/amd64",
			}, config.Config{})
			if err != nil {
				t.Fatalf("select embedded profile for %s: %v", root, err)
			}
			if selection.Source != toolchain.SourceDefault || selection.Profile.ID != testCase.ExpectedProfileID {
				t.Fatalf(
					"selected profile = %q source=%q, want profile=%q source=%q",
					selection.Profile.ID, selection.Source, testCase.ExpectedProfileID, toolchain.SourceDefault,
				)
			}
		})
	}

	runtimes := ecosystems.SupportedPythonRuntimeFamilies()
	if len(runtimes) == 0 {
		t.Fatal("embedded Python runtime policy is empty")
	}
	for _, runtime := range []string{runtimes[0], runtimes[len(runtimes)-1]} {
		for _, manager := range []string{"poetry", "uv", "pip-tools", "requirements"} {
			profileID := fmt.Sprintf(
				"default-python%s-%s",
				strings.ReplaceAll(runtime, ".", ""),
				manager,
			)
			if !embeddedProfiles[profileID] {
				t.Errorf("real-engine matrix omits reviewed boundary profile %q", profileID)
			}
		}
	}
}
