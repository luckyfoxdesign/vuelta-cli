package repopolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type composeDocument struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Build yaml.Node `yaml:"build"`
	Image string    `yaml:"image"`
}

func TestComposeExternalImagesArePinned(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "compose.yml"))
	if err != nil {
		t.Fatalf("read repository compose file: %v", err)
	}
	if err := validateExternalImages(data); err != nil {
		t.Fatalf("repository compose image policy: %v", err)
	}
}

func TestValidateExternalImages(t *testing.T) {
	t.Parallel()

	exactDigest := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		compose string
		wantErr string
	}{
		{
			name:    "exact tag and digest",
			compose: "services:\n  lint:\n    image: example/tool:v1.2.3@sha256:" + exactDigest + "\n",
		},
		{
			name:    "local build",
			compose: "services:\n  test:\n    build: .\n",
		},
		{
			name:    "mutable tag",
			compose: "services:\n  lint:\n    image: example/tool:v1.2.3\n",
			wantErr: "service lint",
		},
		{
			name:    "placeholder digest",
			compose: "services:\n  lint:\n    image: example/tool:v1.2.3@sha256:<digest>\n",
			wantErr: "service lint",
		},
		{
			name:    "short digest",
			compose: "services:\n  lint:\n    image: example/tool:v1.2.3@sha256:" + strings.Repeat("a", 63) + "\n",
			wantErr: "service lint",
		},
		{
			name:    "digest without reviewable tag",
			compose: "services:\n  lint:\n    image: example/tool@sha256:" + exactDigest + "\n",
			wantErr: "service lint",
		},
		{
			name:    "missing external image",
			compose: "services:\n  lint:\n    command: [lint]\n",
			wantErr: "service lint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateExternalImages([]byte(tt.compose))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate exact image reference: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateExternalImages() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func validateExternalImages(data []byte) error {
	var document composeDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse compose file: %w", err)
	}

	names := make([]string, 0, len(document.Services))
	for name := range document.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	var errs []error
	for _, name := range names {
		service := document.Services[name]
		if hasLocalBuild(service.Build) {
			continue
		}
		if !hasTaggedSHA256Digest(service.Image) {
			errs = append(errs, fmt.Errorf(
				"service %s: externally pulled image %q must use <repository>:<tag>@sha256:<64 lowercase hex characters>",
				name,
				service.Image,
			))
		}
	}
	return errors.Join(errs...)
}

func hasLocalBuild(build yaml.Node) bool {
	return build.Kind != 0 && build.Tag != "!!null"
}

func hasTaggedSHA256Digest(reference string) bool {
	if strings.ContainsAny(reference, " \t\r\n") {
		return false
	}

	parts := strings.Split(reference, "@sha256:")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return false
	}
	for _, char := range parts[1] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}

	nameAndTag := parts[0]
	lastSlash := strings.LastIndexByte(nameAndTag, '/')
	lastColon := strings.LastIndexByte(nameAndTag, ':')
	return lastColon > lastSlash && lastColon < len(nameAndTag)-1
}
