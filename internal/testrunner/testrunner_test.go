package testrunner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func installFakeDocker(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\necho fake docker invoked: \"$@\"\nexit %d\n", exitCode)
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func installDockerInvocationMarker(t *testing.T, marker string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n: > \"$FAKE_DOCKER_MARKER\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_MARKER", marker)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func writeCompose(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeFixture(t *testing.T, dir, fixture string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", fixture, "docker-compose.test.yml"))
	if err != nil {
		t.Fatal(err)
	}
	writeCompose(t, dir, "docker-compose.test.yml", string(data))
}

var validCompose = fmt.Sprintf(`
services:
  test:
    image: golang:1.26-alpine@sha256:%s
    user: "65532:65532"
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    cpus: "1"
    mem_limit: 1g
    pids_limit: 256
    networks: [testnet]
    command: ["go", "test", "./..."]
networks:
  testnet:
    internal: true
`, strings.Repeat("1", 64))

func TestRunPassesWithValidCompose(t *testing.T) {
	installFakeDocker(t, 0)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	res, err := Run(context.Background(), dir, profile, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Passed {
		t.Fatalf("expected pass, got fail: %s", res.Output)
	}
}

func TestRunFailsWhenComposeCommandFails(t *testing.T) {
	installFakeDocker(t, 1)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	res, err := Run(context.Background(), dir, profile, time.Second)
	if err != nil {
		t.Fatalf("Run should not return a Go error for a failing test suite: %v", err)
	}
	if res.Passed {
		t.Fatal("expected Passed=false")
	}
}

func TestRunRejectsPrivileged(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    build: .
    privileged: true
`)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected privileged service to be rejected")
	}
}

func TestRunRejectsHostNetwork(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    build: .
    network_mode: host
`)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected network_mode host to be rejected")
	}
}

func TestRunRejectsDockerSocketMount(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    build: .
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected docker.sock mount to be rejected")
	}
}

func TestRunRejectsAbsoluteHostMount(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    build: .
    volumes:
      - /etc/passwd:/etc/passwd
`)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected absolute host mount to be rejected")
	}
}

func TestRunRejectsEnvFile(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    build: .
    env_file: .env
`)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected env_file to be rejected")
	}
}

func TestRunRejectsMutableImageTag(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    image: golang:latest
`)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected mutable image tag to be rejected")
	}
}

func TestRunRejectsUnknownService(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)
	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "does-not-exist"}
	err := func() error {
		_, err := Run(context.Background(), dir, profile, time.Second)
		return err
	}()
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected unknown service error, got %v", err)
	}
}

func TestRunRejectsComposePolicyBypassBeforeDocker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture requires a POSIX filesystem")
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		composeFile string
		compose     string
		fixture     string
		setup       func(t *testing.T, dir string)
		want        string
	}{
		{
			name:        "parent compose path",
			composeFile: "../outside.yml",
			want:        "escapes the sandbox",
		},
		{
			name:        "compose symlink",
			composeFile: "linked.yml",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Symlink(filepath.Join(outside, "outside.txt"), filepath.Join(dir, "linked.yml")); err != nil {
					t.Fatal(err)
				}
			},
			want: "symlink",
		},
		{
			name:    "relative bind outside sandbox",
			fixture: "bad-compose-relative-bind-outside",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "outside"), []byte("outside"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "resolves outside the sandbox",
		},
		{
			name: "undeclared named volume",
			compose: `
services:
  test:
    build: .
    volumes:
      - cache:/cache
`,
			want: "must be declared",
		},
		{
			name:    "external named volume",
			fixture: "bad-compose-external-volume",
			want:    "must be local",
		},
		{
			name:    "dependency privileged",
			fixture: "bad-compose-dependency-privileged",
			want:    "service \"helper\": privileged",
		},
		{
			name:    "device",
			fixture: "bad-compose-devices",
			want:    "devices are not allowed",
		},
		{
			name:    "capability addition",
			fixture: "bad-compose-cap-add",
			want:    "cap_add is not allowed",
		},
		{
			name:    "privileged fixture",
			fixture: "bad-compose-privileged",
			want:    "privileged is not allowed",
		},
		{
			name:    "host network fixture",
			fixture: "bad-compose-network-host",
			want:    "network_mode host is not allowed",
		},
		{
			name:    "host pid fixture",
			fixture: "bad-compose-pid-host",
			want:    "pid host is not allowed",
		},
		{
			name:    "host ipc fixture",
			fixture: "bad-compose-ipc-host",
			want:    "ipc host is not allowed",
		},
		{
			name:    "docker socket fixture",
			fixture: "bad-compose-docker-socket",
			want:    "docker socket mount is not allowed",
		},
		{
			name:    "absolute host mount fixture",
			fixture: "bad-compose-absolute-host-mount",
			want:    "must be a sandbox-relative path",
		},
		{
			name:    "env file fixture",
			fixture: "bad-compose-env-file",
			want:    "env_file is not allowed",
		},
		{
			name:    "mutable image fixture",
			fixture: "bad-compose-mutable-image",
			want:    "must be pinned by digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(t.TempDir(), "docker-invoked")
			installDockerInvocationMarker(t, marker)
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			if tt.compose != "" {
				writeCompose(t, dir, "docker-compose.test.yml", tt.compose)
			}
			if tt.fixture != "" {
				writeFixture(t, dir, tt.fixture)
			}
			composeFile := tt.composeFile
			if composeFile == "" {
				composeFile = "docker-compose.test.yml"
			}
			_, err := Run(context.Background(), dir, config.TestProfile{ComposeFile: composeFile, Service: "test"}, time.Second)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected policy error containing %q, got %v", tt.want, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("docker was invoked before policy rejection: %v", err)
			}
		})
	}
}

func TestRunAllowsDeclaredLocalNamedVolume(t *testing.T) {
	installFakeDocker(t, 0)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", `
services:
  test:
    image: golang:1.26-alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111
    user: "65532:65532"
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    cpus: "1"
    mem_limit: 1g
    pids_limit: 256
    networks: [testnet]
    volumes:
      - cache:/cache
volumes:
  cache: {}
networks:
  testnet:
    internal: true
`)

	res, err := Run(context.Background(), dir, config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Passed {
		t.Fatalf("expected pass, got fail: %s", res.Output)
	}
}

func TestRunTimesOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nsleep 5\n"
	scriptDir := t.TempDir()
	path := filepath.Join(scriptDir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", scriptDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	profile := config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}
	_, err := Run(context.Background(), dir, profile, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestRunRejectsMissingRunnerHardening(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"root user", "user: \"65532:65532\"", "user: \"0\"", "non-root UID"},
		{"cap drop", "cap_drop: [\"ALL\"]", "cap_drop: []", "cap_drop"},
		{"no new privileges", "security_opt: [\"no-new-privileges:true\"]", "security_opt: []", "no-new-privileges"},
		{"pids limit", "pids_limit: 256", "pids_limit: 0", "pids_limit"},
		{"external network", "networks: [testnet]", "networks: [outside]", "network \"outside\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeCompose(t, dir, "docker-compose.test.yml", strings.Replace(validCompose, tt.old, tt.new, 1))
			_, err := Run(context.Background(), dir, config.TestProfile{ComposeFile: "docker-compose.test.yml", Service: "test"}, time.Second)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}
