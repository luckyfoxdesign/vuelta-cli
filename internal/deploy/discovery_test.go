package deploy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"gopkg.in/yaml.v3"
)

func TestDiscoverDerivesZeroWriteComposeContract(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "compose.yml", `
name: example
services:
  api:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: runtime
    container_name: api
    networks: [private, public]
    healthcheck:
      test: ["CMD", "check", "http://localhost:8000/health"]
  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: runtime
    networks: [private]
  test:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: test
  lint:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: lint
    profiles: [tools]
networks:
  private: {}
  public:
    external: true
`)
	writeFixture(t, root, "compose.prod.yml", `
services:
  api:
    env_file: .env
    read_only: true
  worker:
    env_file: .env
`)
	if err := os.MkdirAll(filepath.Join(root, "alembic", "versions"), 0o755); err != nil {
		t.Fatal(err)
	}

	contract, err := Discover(context.Background(), config.Workspace{
		Name: "api", Path: root, Branch: "main", Remote: "origin",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if contract.RepositoryWrites {
		t.Fatal("discovery must never authorize repository writes")
	}
	if !slices.Equal(contract.ComposeFiles, []string{"compose.yml", "compose.prod.yml"}) {
		t.Fatalf("compose files = %#v", contract.ComposeFiles)
	}
	if contract.TrafficService != "api" || contract.StableUpstream != "api" || contract.InternalPort != 8000 {
		t.Fatalf("traffic contract = %#v", contract)
	}
	if !slices.Equal(contract.ExternalNetworks, []string{"public"}) {
		t.Fatalf("external networks = %#v", contract.ExternalNetworks)
	}
	if len(contract.Services) != 2 || contract.Services[0].Role != "web" || contract.Services[1].Role != "singleton" {
		t.Fatalf("services = %#v", contract.Services)
	}
	if slices.Contains(contract.Blockers, "release_services_use_different_builds") {
		t.Fatalf("tooling-only Compose services entered the release contract: %#v", contract.Blockers)
	}
	if !slices.Equal(contract.MigrationPaths, []string{"alembic/versions"}) {
		t.Fatalf("migration paths = %#v", contract.MigrationPaths)
	}
	if contract.Fingerprint == "" {
		t.Fatal("fingerprint is required")
	}
	if !slices.Contains(contract.Blockers, "github_repository_unresolved") ||
		!slices.Contains(contract.Blockers, "git_commit_unresolved") {
		t.Fatalf("expected only Git identity blockers in fixture: %#v", contract.Blockers)
	}
}

func TestDiscoverFailsClosedOnAmbiguousComposeAndMissingHealth(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "compose.yml", "services:\n  api:\n    build: .\n")
	writeFixture(t, root, "docker-compose.yml", "services:\n  api:\n    build: .\n")

	contract, err := Discover(context.Background(), config.Workspace{Name: "api", Path: root})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !slices.Contains(contract.Blockers, "compose_group_0_ambiguous") {
		t.Fatalf("blockers = %#v", contract.Blockers)
	}
	if !slices.Contains(contract.Blockers, "healthy_web_service_not_detected") {
		t.Fatalf("blockers = %#v", contract.Blockers)
	}
}

func TestBuildSpecRejectsParentEscape(t *testing.T) {
	var document composeDocument
	data := []byte("services:\n  api:\n    build:\n      context: ../outside\n")
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildSpec(document.Services["api"].Build); err == nil {
		t.Fatal("expected parent escape rejection")
	}
}

func writeFixture(t *testing.T, root, relative, body string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
