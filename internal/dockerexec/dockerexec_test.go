package dockerexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func executable(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testEndpoint() Endpoint {
	return Endpoint{SocketPath: "/approved/docker.sock", Expected: DaemonIdentity{
		ID: "daemon-approved", ServerVersion: "28.3.2", OperatingSystem: "linux", Architecture: "arm64",
		MinimumAPIVersion: "1.44", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"},
	}}
}

func testEndpointValidator(Endpoint) (string, error) { return "/approved/docker.sock", nil }

func daemonProbeResult(request Request) (Result, bool) {
	if len(request.Args) < 3 || request.Args[0] != "--host" || request.Args[1] != "unix:///approved/docker.sock" {
		return Result{}, false
	}
	switch request.Args[2] {
	case "version":
		return Result{Stdout: []byte(`{"server_version":"28.3.2","api_version":"1.49","os":"linux","architecture":"arm64"}`)}, true
	case "info":
		return Result{Stdout: []byte(`{"id":"daemon-approved","security_options":["name=seccomp,profile=builtin"]}`)}, true
	default:
		return Result{}, false
	}
}

func TestExecutorBindsAbsolutePathOnceAndUsesAllowlistedEnvironment(t *testing.T) {
	approved := executable(t, 0o755)
	configDir := filepath.Join(t.TempDir(), "docker-config")
	resolveCalls := 0
	var paths []string
	var environments [][]string
	executor := New(Options{
		Resolver: func(name string) (string, error) {
			resolveCalls++
			if name != "docker" {
				t.Fatalf("resolver name = %q", name)
			}
			return approved, nil
		},
		ConfigDir: configDir,
		Endpoint:  testEndpoint(), EndpointValidator: testEndpointValidator,
		CommandRunner: func(_ context.Context, path string, request Request, env []string) (Result, error) {
			paths = append(paths, path)
			environments = append(environments, append([]string(nil), env...))
			if result, ok := daemonProbeResult(request); ok {
				return result, nil
			}
			if !reflect.DeepEqual(request.Args, []string{"--host", "unix:///approved/docker.sock", "ps"}) {
				t.Fatalf("caller argv = %#v", request.Args)
			}
			return Result{}, nil
		},
	})

	for name, value := range map[string]string{
		"PATH": "/hostile/bin", "DOCKER_HOST": "tcp://attacker.invalid:2375",
		"DOCKER_CONTEXT": "hostile", "DOCKER_CONFIG": "/hostile/config",
		"DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/hostile/certs",
		"HTTP_PROXY": "http://attacker.invalid", "HTTPS_PROXY": "http://attacker.invalid",
		"ALL_PROXY": "socks5://attacker.invalid", "NO_PROXY": "*", "HOME": "/hostile/home",
	} {
		t.Setenv(name, value)
	}

	request := Request{Args: []string{"ps"}, Env: map[string]string{"VUELTA_IMAGE": "registry.example/app@sha256:abc"}}
	if _, err := executor.Run(context.Background(), request); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	t.Setenv("PATH", "/different/hostile/bin")
	t.Setenv("DOCKER_HOST", "unix:///attacker.sock")
	if _, err := executor.Run(context.Background(), request); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	absolute, err := filepath.Abs(approved)
	if err != nil {
		t.Fatal(err)
	}
	if resolveCalls != 1 {
		t.Fatalf("resolver called %d times, want 1", resolveCalls)
	}
	if !reflect.DeepEqual(paths, []string{absolute, absolute, absolute, absolute}) {
		t.Fatalf("command paths = %#v, want exact absolute path %q", paths, absolute)
	}
	wantProbeEnv := []string{"DOCKER_CONFIG=" + configDir, "HOME=" + configDir, "TMPDIR=" + configDir}
	wantCallerEnv := []string{"DOCKER_CONFIG=" + configDir, "HOME=" + configDir, "TMPDIR=" + configDir, "VUELTA_IMAGE=registry.example/app@sha256:abc"}
	for i, got := range environments {
		want := wantCallerEnv
		if i < 2 {
			want = wantProbeEnv
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("child environment[%d] = %#v, want %#v", i, got, want)
		}
	}
	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "{}" {
		t.Fatalf("isolated Docker config = %q", data)
	}
}

func TestExecutorRejectsUnapprovedEnvironment(t *testing.T) {
	executor := New(Options{
		Resolver:  func(string) (string, error) { return executable(t, 0o755), nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
		Endpoint:  testEndpoint(), EndpointValidator: testEndpointValidator,
	})
	_, err := executor.Run(context.Background(), Request{
		Args: []string{"version"}, Env: map[string]string{"DOCKER_HOST": "tcp://attacker.invalid:2375"},
	})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected environment rejection, got %v", err)
	}
}

func TestDockerConfigTempRootAvoidsDarwinUserTempDirectory(t *testing.T) {
	if got := dockerConfigTempRoot("darwin"); got != "/private/tmp" {
		t.Fatalf("darwin temp root = %q", got)
	}
	if got := dockerConfigTempRoot("linux"); got != "" {
		t.Fatalf("linux temp root = %q, want platform default", got)
	}
}

func TestExecutorRejectsGroupWritableBinary(t *testing.T) {
	executor := New(Options{
		Resolver:  func(string) (string, error) { return executable(t, 0o775), nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
		Endpoint:  testEndpoint(), EndpointValidator: testEndpointValidator,
	})
	if _, err := executor.Path(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected writable binary rejection, got %v", err)
	}
}

func TestRunCommandCapturesExitCodeAndRedactedStderrTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\nif [ \"$3\" = version ]; then echo '{\"server_version\":\"28.3.2\",\"api_version\":\"1.49\",\"os\":\"linux\",\"architecture\":\"arm64\"}'; exit 0; fi\nif [ \"$3\" = info ]; then echo '{\"id\":\"daemon-approved\",\"security_options\":[\"name=seccomp,profile=builtin\"]}'; exit 0; fi\necho 'permission denied: token=supersecret123' 1>&2\nexit 3\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	executor := New(Options{
		Resolver:  func(string) (string, error) { return path, nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
		Endpoint:  testEndpoint(), EndpointValidator: testEndpointValidator,
	})
	_, err := executor.Run(context.Background(), Request{
		Args:   []string{"ps"},
		Stderr: Capture{Mode: Tail, Bytes: 4 << 10},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "docker command failed" {
		t.Fatalf("top-level error leaked detail: %q", err.Error())
	}
	category, exitCode, detail := Classify(err)
	if exitCode != 3 {
		t.Fatalf("exit code = %d, want 3", exitCode)
	}
	if category != "permission" {
		t.Fatalf("category = %q, want permission", category)
	}
	if strings.Contains(detail, "supersecret123") {
		t.Fatalf("detail leaked secret: %q", detail)
	}
	if !strings.Contains(detail, "<redacted>") {
		t.Fatalf("detail did not redact credential-like text: %q", detail)
	}
}

func TestRunCommandNeverCapturesUndiscardedStderr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\nif [ \"$3\" = version ]; then echo '{\"server_version\":\"28.3.2\",\"api_version\":\"1.49\",\"os\":\"linux\",\"architecture\":\"arm64\"}'; exit 0; fi\nif [ \"$3\" = info ]; then echo '{\"id\":\"daemon-approved\",\"security_options\":[\"name=seccomp,profile=builtin\"]}'; exit 0; fi\necho 'permission denied' 1>&2\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	executor := New(Options{
		Resolver:  func(string) (string, error) { return path, nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
		Endpoint:  testEndpoint(), EndpointValidator: testEndpointValidator,
	})
	_, err := executor.Run(context.Background(), Request{Args: []string{"ps"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	_, exitCode, detail := Classify(err)
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if detail != "" {
		t.Fatalf("detail = %q, want empty when the caller never captured stderr", detail)
	}
}

func TestExecutorRejectsUnexpectedDaemonIdentityBeforeCallerCommand(t *testing.T) {
	called := false
	executor := New(Options{
		Resolver:  func(string) (string, error) { return executable(t, 0o755), nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"), Endpoint: testEndpoint(), EndpointValidator: testEndpointValidator,
		CommandRunner: func(_ context.Context, _ string, request Request, _ []string) (Result, error) {
			if request.Args[2] == "version" {
				return Result{Stdout: []byte(`{"server_version":"28.3.2","api_version":"1.49","os":"linux","architecture":"arm64"}`)}, nil
			}
			if request.Args[2] == "info" {
				return Result{Stdout: []byte(`{"id":"attacker-daemon","security_options":["name=seccomp,profile=builtin"]}`)}, nil
			}
			called = true
			return Result{}, nil
		},
	})
	_, err := executor.Run(context.Background(), Request{Args: []string{"ps"}})
	if err == nil || !strings.Contains(err.Error(), "identity does not match") {
		t.Fatalf("unexpected identity error = %v", err)
	}
	if called {
		t.Fatal("caller command ran against an unexpected daemon")
	}
}

func TestExecutorBoundsDaemonIdentityProbe(t *testing.T) {
	previous := daemonProbeTimeout
	daemonProbeTimeout = 10 * time.Millisecond
	t.Cleanup(func() { daemonProbeTimeout = previous })

	executor := New(Options{
		Resolver:  func(string) (string, error) { return executable(t, 0o755), nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"), Endpoint: testEndpoint(), EndpointValidator: testEndpointValidator,
		CommandRunner: func(ctx context.Context, _ string, _ Request, _ []string) (Result, error) {
			<-ctx.Done()
			return Result{}, ctx.Err()
		},
	})
	err := executor.Verify(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify error = %v, want deadline exceeded", err)
	}
}

func TestAttestDaemonRejectsVersionPlatformAPIAndSecurityDrift(t *testing.T) {
	expected := testEndpoint().Expected
	validVersion := versionIdentity{ServerVersion: "28.3.2", APIVersion: "1.49", OperatingSystem: "linux", Architecture: "arm64"}
	validInfo := infoIdentity{ID: "daemon-approved", SecurityOptions: []string{"name=seccomp,profile=builtin"}}
	tests := []struct {
		name    string
		version versionIdentity
		info    infoIdentity
		want    string
	}{
		{name: "server version", version: versionIdentity{ServerVersion: "28.3.3", APIVersion: "1.49", OperatingSystem: "linux", Architecture: "arm64"}, info: validInfo, want: "server version"},
		{name: "platform", version: versionIdentity{ServerVersion: "28.3.2", APIVersion: "1.49", OperatingSystem: "linux", Architecture: "amd64"}, info: validInfo, want: "platform"},
		{name: "api", version: versionIdentity{ServerVersion: "28.3.2", APIVersion: "1.43", OperatingSystem: "linux", Architecture: "arm64"}, info: validInfo, want: "API version"},
		{name: "security option", version: validVersion, info: infoIdentity{ID: "daemon-approved", SecurityOptions: []string{"name=cgroupns"}}, want: "security option"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := attestDaemon(expected, test.version, test.info); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("attest error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestClassifyOutputLimitAndContextErrors(t *testing.T) {
	if category, exitCode, _ := Classify(&OutputLimitError{Stream: "stdout", Limit: 10}); category != "output_limit" || exitCode != -1 {
		t.Fatalf("output limit classify = %q/%d", category, exitCode)
	}
	if category, exitCode, _ := Classify(context.DeadlineExceeded); category != "timeout" || exitCode != -1 {
		t.Fatalf("deadline classify = %q/%d", category, exitCode)
	}
	if category, exitCode, _ := Classify(context.Canceled); category != "cancelled" || exitCode != -1 {
		t.Fatalf("cancel classify = %q/%d", category, exitCode)
	}
}
