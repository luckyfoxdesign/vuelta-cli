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
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
)

func fakeDockerExecutor(t *testing.T, path string) dockerexec.Runner {
	t.Helper()
	return dockerexec.New(dockerexec.Options{Resolver: func(string) (string, error) { return path, nil }})
}

func installFakeDocker(t *testing.T, exitCode int) dockerexec.Runner {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = down ] && exit 0; done\necho fake docker invoked: \"$@\"\nexit %d\n", exitCode)
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakeDockerExecutor(t, path)
}

func installDockerInvocationMarker(t *testing.T, marker string) dockerexec.Runner {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	script := fmt.Sprintf("#!/bin/sh\n: > %q\n", marker)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakeDockerExecutor(t, path)
}

func installCapturingFakeDocker(t *testing.T, argsPath, modelPath string) dockerexec.Runner {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker shell script requires a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
case " $* " in
*" run "*) printf '%%s\n' "$@" > %q ;;
esac
previous=
for argument in "$@"; do
  if [ "$previous" = "-f" ]; then
    /bin/cp "$argument" %q
  fi
  previous="$argument"
done
`, argsPath, modelPath)
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakeDockerExecutor(t, path)
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

func verificationStep(composeFile, service string) config.VerificationStep {
	return config.VerificationStep{
		Name: "test", ComposeFile: composeFile, Service: service,
		Command: []string{"go", "test", "./..."}, TimeoutSeconds: 60,
		Required: true, SuccessExitCodes: []int{0},
	}
}

func TestRunPassesWithValidCompose(t *testing.T) {
	docker := installFakeDocker(t, 0)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	profile := verificationStep("docker-compose.test.yml", "test")
	res, err := RunWithDocker(context.Background(), docker, dir, profile, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Passed {
		t.Fatalf("expected pass, got fail: %s", res.Output)
	}
}

func TestValidateComposeAcceptsDigestPinnedMinimalService(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "docker-compose.test.yml")
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	normalized, err := validateCompose(dir, composePath, "test")
	if err != nil {
		t.Fatalf("validateCompose: %v", err)
	}
	serialized := string(normalized)
	if strings.Contains(serialized, "build:") || !strings.Contains(serialized, "@sha256:") {
		t.Fatalf("unexpected normalized model:\n%s", serialized)
	}
}

func TestRunExecutesSerializedValidatedModelWithSanitizedEnvironment(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "args")
	modelPath := filepath.Join(t.TempDir(), "validated-compose.yml")
	docker := installCapturingFakeDocker(t, argsPath, modelPath)
	t.Setenv("COMPOSE_FILE", "host-controlled-compose.yml")
	t.Setenv("HOST_SECRET_SENTINEL", "must-not-be-inherited")
	writeCompose(t, dir, "repository-compose.yml", validCompose+"\n# repository-only-marker\n")

	step := verificationStep("repository-compose.yml", "test")
	step.Command = []string{"go", "test", "./explicit"}
	result, err := RunWithDocker(context.Background(), docker, dir, step, time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass, got fail: %s", result.Output)
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), "repository-compose.yml") {
		t.Fatalf("docker received the repository compose path: %s", args)
	}
	if !strings.Contains(string(args), "--env-file") || !strings.Contains(string(args), "-f") {
		t.Fatalf("docker did not receive normalized compose and empty env files: %s", args)
	}
	if !strings.Contains(string(args), "--entrypoint\ngo\ntest\ntest\n./explicit") {
		t.Fatalf("docker did not receive the explicit entrypoint and argv override: %s", args)
	}
	model, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(model), "repository-only-marker") || strings.Contains(string(model), "build:") {
		t.Fatalf("docker received repository-only data instead of the validated model:\n%s", model)
	}
	if strings.Contains(string(model), "./...") {
		t.Fatalf("normalized model retained the inherited service command:\n%s", model)
	}
}

func TestRunFailsWhenComposeCommandFails(t *testing.T) {
	docker := installFakeDocker(t, 1)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	profile := verificationStep("docker-compose.test.yml", "test")
	res, err := RunWithDocker(context.Background(), docker, dir, profile, time.Second)
	if err != nil {
		t.Fatalf("Run should not return a Go error for a failing test suite: %v", err)
	}
	if res.Passed {
		t.Fatal("expected Passed=false")
	}
}

func TestRunUsesExplicitSuccessExitCodes(t *testing.T) {
	docker := installFakeDocker(t, 1)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)
	step := verificationStep("docker-compose.test.yml", "test")
	step.SuccessExitCodes = []int{1}
	result, err := RunWithDocker(context.Background(), docker, dir, step, time.Second)
	if err != nil || !result.Passed {
		t.Fatalf("explicit success exit code was not honored: result=%+v err=%v", result, err)
	}
}

func TestRunProfileExecutesMultipleRequiredSteps(t *testing.T) {
	docker := installFakeDocker(t, 0)
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)
	first := verificationStep("docker-compose.test.yml", "test")
	first.Name = "test"
	second := verificationStep("docker-compose.test.yml", "test")
	second.Name = "build"
	second.Command = []string{"go", "build", "./..."}
	result, err := RunProfileWithDocker(context.Background(), docker, dir, config.VerificationProfile{
		Version: config.VerificationVersion, State: config.VerificationReady, Steps: []config.VerificationStep{first, second},
	})
	if err != nil || !result.Passed {
		t.Fatalf("multi-step profile failed: result=%+v err=%v", result, err)
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
	profile := verificationStep("docker-compose.test.yml", "test")
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
	profile := verificationStep("docker-compose.test.yml", "test")
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
	profile := verificationStep("docker-compose.test.yml", "test")
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
	profile := verificationStep("docker-compose.test.yml", "test")
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
	profile := verificationStep("docker-compose.test.yml", "test")
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
	profile := verificationStep("docker-compose.test.yml", "test")
	if _, err := Run(context.Background(), dir, profile, time.Second); err == nil {
		t.Fatal("expected mutable image tag to be rejected")
	}
}

func TestRunRejectsUnknownService(t *testing.T) {
	dir := t.TempDir()
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)
	profile := verificationStep("docker-compose.test.yml", "does-not-exist")
	err := func() error {
		_, err := Run(context.Background(), dir, profile, time.Second)
		return err
	}()
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected unknown service error, got %v", err)
	}
}

func TestRunRejectsUnsafeCommandBeforeDocker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "docker-invoked")
	docker := installDockerInvocationMarker(t, marker)
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	step := verificationStep("docker-compose.test.yml", "test")
	step.Command = []string{"sh", "-c", "go test ./..."}
	_, err := RunWithDocker(context.Background(), docker, dir, step, time.Second)
	if err == nil || !strings.Contains(err.Error(), "shell executables") {
		t.Fatalf("expected explicit command policy error, got %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("docker was invoked before run argument rejection: %v", err)
	}
}

func TestInterpolationErrorDoesNotRevealHostValue(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "bad-compose-interpolation-user")
	t.Setenv("HOST_UID", "sensitive-host-value")

	_, err := Run(context.Background(), dir, verificationStep("docker-compose.test.yml", "test"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "interpolation is not allowed") {
		t.Fatalf("expected interpolation policy error, got %v", err)
	}
	if strings.Contains(err.Error(), "sensitive-host-value") {
		t.Fatal("policy error disclosed an inherited host value")
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
			name: "bind source symlink",
			compose: `
services:
  test:
    volumes:
      - ./linked-source:/data:ro
`,
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Symlink(filepath.Join(outside, "outside.txt"), filepath.Join(dir, "linked-source")); err != nil {
					t.Fatal(err)
				}
			},
			want: "symlink",
		},
		{
			name: "undeclared named volume",
			compose: `
services:
  test:
    volumes:
      - cache:/cache
`,
			want: "must be declared",
		},
		{
			name:    "external named volume",
			fixture: "bad-compose-external-volume",
			want:    "declared empty",
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
			want:    "network_mode is not allowed",
		},
		{
			name:    "host pid fixture",
			fixture: "bad-compose-pid-host",
			want:    "pid is not allowed",
		},
		{
			name:    "host ipc fixture",
			fixture: "bad-compose-ipc-host",
			want:    "ipc is not allowed",
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
		{
			name:    "build-only service",
			fixture: "bad-compose-build-only",
			want:    "build is not allowed",
		},
		{
			name:    "detailed build attributes",
			fixture: "bad-compose-build-detailed",
			want:    "build is not allowed",
		},
		{
			name:    "build ssh socket",
			fixture: "bad-compose-build-ssh",
			want:    "build is not allowed",
		},
		{
			name:    "build additional context",
			fixture: "bad-compose-build-additional-context",
			want:    "build is not allowed",
		},
		{
			name:    "pid interpolation",
			fixture: "bad-compose-interpolation-pid",
			want:    "interpolation is not allowed",
		},
		{
			name:    "user interpolation",
			fixture: "bad-compose-interpolation-user",
			want:    "interpolation is not allowed",
		},
		{
			name:    "extra security option",
			fixture: "bad-compose-security-opt",
			want:    "security_opt",
		},
		{
			name:    "unknown service field",
			fixture: "bad-compose-unknown-service-field",
			want:    "mystery_escape_hatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(t.TempDir(), "docker-invoked")
			docker := installDockerInvocationMarker(t, marker)
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
			_, err := RunWithDocker(context.Background(), docker, dir, verificationStep(composeFile, "test"), time.Second)
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
	docker := installFakeDocker(t, 0)
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

	res, err := RunWithDocker(context.Background(), docker, dir, verificationStep("docker-compose.test.yml", "test"), time.Second)
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
	cleanupMarker := filepath.Join(t.TempDir(), "cleanup")
	script := fmt.Sprintf("#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = down ] && { : > %q; exit 0; }; done\nsleep 5\n", cleanupMarker)
	scriptDir := t.TempDir()
	path := filepath.Join(scriptDir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	docker := fakeDockerExecutor(t, path)
	writeCompose(t, dir, "docker-compose.test.yml", validCompose)

	profile := verificationStep("docker-compose.test.yml", "test")
	_, err := RunWithDocker(context.Background(), docker, dir, profile, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if _, statErr := os.Stat(cleanupMarker); statErr != nil {
		t.Fatalf("timed-out verification did not run cleanup: %v", statErr)
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
		{"named user", "user: \"65532:65532\"", "user: \"nobody\"", "non-root UID"},
		{"root group", "user: \"65532:65532\"", "user: \"65532:0\"", "non-root UID"},
		{"cap drop", "cap_drop: [\"ALL\"]", "cap_drop: []", "cap_drop"},
		{"no new privileges", "security_opt: [\"no-new-privileges:true\"]", "security_opt: []", "no-new-privileges"},
		{"cpu limit", "cpus: \"1\"", "cpus: \"0\"", "cpus"},
		{"memory limit", "mem_limit: 1g", "mem_limit: 0", "mem_limit"},
		{"pids limit", "pids_limit: 256", "pids_limit: 0", "pids_limit"},
		{"external network", "networks: [testnet]", "networks: [outside]", "network \"outside\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeCompose(t, dir, "docker-compose.test.yml", strings.Replace(validCompose, tt.old, tt.new, 1))
			_, err := Run(context.Background(), dir, verificationStep("docker-compose.test.yml", "test"), time.Second)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}
