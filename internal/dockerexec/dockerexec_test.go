package dockerexec

import (
	"context"
	"errors"
	"fmt"
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
	valid := DaemonIdentity{ID: "daemon-approved", ServerVersion: "28.3.2", MinimumAPIVersion: "1.49", OperatingSystem: "linux", Architecture: "arm64", RequiredSecurityOptions: []string{"name=seccomp,profile=builtin"}}
	tests := []struct {
		name   string
		actual DaemonIdentity
		want   string
	}{
		{name: "server version", actual: DaemonIdentity{ID: valid.ID, ServerVersion: "28.3.3", MinimumAPIVersion: valid.MinimumAPIVersion, OperatingSystem: valid.OperatingSystem, Architecture: valid.Architecture, RequiredSecurityOptions: valid.RequiredSecurityOptions}, want: "server version"},
		{name: "platform", actual: DaemonIdentity{ID: valid.ID, ServerVersion: valid.ServerVersion, MinimumAPIVersion: valid.MinimumAPIVersion, OperatingSystem: valid.OperatingSystem, Architecture: "amd64", RequiredSecurityOptions: valid.RequiredSecurityOptions}, want: "platform"},
		{name: "api", actual: DaemonIdentity{ID: valid.ID, ServerVersion: valid.ServerVersion, MinimumAPIVersion: "1.43", OperatingSystem: valid.OperatingSystem, Architecture: valid.Architecture, RequiredSecurityOptions: valid.RequiredSecurityOptions}, want: "API version"},
		{name: "security option", actual: DaemonIdentity{ID: valid.ID, ServerVersion: valid.ServerVersion, MinimumAPIVersion: valid.MinimumAPIVersion, OperatingSystem: valid.OperatingSystem, Architecture: valid.Architecture, RequiredSecurityOptions: []string{"name=cgroupns"}}, want: "security option"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := attestDaemon(expected, test.actual); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("attest error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestNormalizeArchitectureAliases(t *testing.T) {
	for input, want := range map[string]string{"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"} {
		got, err := NormalizeArchitecture(input)
		if err != nil || got != want {
			t.Fatalf("NormalizeArchitecture(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeArchitecture("riscv64"); err == nil {
		t.Fatal("unsupported architecture succeeded")
	}
}

func TestProbeUsesExplicitSocketAndIsolatedEnvironment(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "docker-config")
	call := 0
	identity, err := ProbeWithOptions(context.Background(), ProbeOptions{
		Resolver:  func(string) (string, error) { return executable(t, 0o755), nil },
		ConfigDir: configDir, SocketPath: "/approved/docker.sock",
		EndpointValidator: testEndpointValidator,
		CommandRunner: func(_ context.Context, _ string, request Request, environment []string) (Result, error) {
			call++
			joined := strings.Join(environment, "\n")
			for _, forbidden := range []string{"DOCKER_HOST=", "DOCKER_CONTEXT=", "HTTP_PROXY=", "HTTPS_PROXY="} {
				if strings.Contains(joined, forbidden) {
					t.Fatalf("probe inherited %s in %v", forbidden, environment)
				}
			}
			if len(request.Args) < 3 || request.Args[0] != "--host" || request.Args[1] != "unix:///approved/docker.sock" {
				t.Fatalf("probe args = %v", request.Args)
			}
			if call == 1 {
				return Result{Stdout: []byte(`{"server_version":"28.3.2","api_version":"1.49","os":"linux","architecture":"aarch64"}`)}, nil
			}
			return Result{Stdout: []byte(`{"id":"daemon-approved","security_options":["name=seccomp,profile=builtin"]}`)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if call != 2 || identity.Architecture != "arm64" || identity.ID != "daemon-approved" {
		t.Fatalf("identity = %#v, calls = %d", identity, call)
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

// TestMain lets the test binary double as a fake multi-call Docker CLI: when
// it is started under the name "docker" it answers the daemon identity probe,
// and under any other name it fails like OrbStack's docker-tools does.
func TestMain(m *testing.M) {
	if name := filepath.Base(os.Args[0]); name == "docker-tools" {
		fmt.Fprintf(os.Stderr, "unsupported argv0 %q\n", name)
		os.Exit(1)
	}
	if filepath.Base(os.Args[0]) == "docker" {
		if len(os.Args) > 3 {
			switch os.Args[3] {
			case "version":
				fmt.Println(`{"server_version":"28.3.2","api_version":"1.49","os":"linux","architecture":"arm64"}`)
			case "info":
				fmt.Println(`{"id":"daemon-approved","security_options":["name=seccomp,profile=builtin"]}`)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func copyTestBinary(t *testing.T, dest string, mode os.FileMode) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, mode); err != nil {
		t.Fatal(err)
	}
}

// multiCallCLI mimics OrbStack: docker is a symlink to a differently named
// multi-call binary that chooses its behavior from argv[0].
func multiCallCLI(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "docker-tools")
	copyTestBinary(t, target, mode)
	link := filepath.Join(dir, "docker")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func multiCallExecutor(t *testing.T, cli string) *Executor {
	t.Helper()
	return New(Options{
		Resolver:  func(string) (string, error) { return cli, nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
		Endpoint:  testEndpoint(), EndpointValidator: testEndpointValidator,
	})
}

func TestExecutorStartsMultiCallCLIUnderDockerName(t *testing.T) {
	executor := multiCallExecutor(t, multiCallCLI(t, 0o755))
	if _, err := executor.Run(context.Background(), Request{Args: []string{"ps"}}); err != nil {
		t.Fatalf("multi-call CLI rejected: %v", err)
	}
	path, err := executor.Path()
	if err != nil || filepath.Base(path) != "docker-tools" {
		t.Fatalf("executed path = %q, %v; want the verified symlink target", path, err)
	}
}

func TestExecutorStartsPlainBinaryUnderDockerName(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "docker")
	copyTestBinary(t, plain, 0o755)
	executor := multiCallExecutor(t, plain)
	if err := executor.Verify(context.Background()); err != nil {
		t.Fatalf("plain CLI rejected: %v", err)
	}
}

func TestExecutorRejectsWritableSymlinkTarget(t *testing.T) {
	executor := multiCallExecutor(t, multiCallCLI(t, 0o775))
	if _, err := executor.Path(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected writable symlink target rejection, got %v", err)
	}
}

func TestExecutorRejectsNonExecutableSymlinkTarget(t *testing.T) {
	executor := multiCallExecutor(t, multiCallCLI(t, 0o644))
	if _, err := executor.Path(); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("expected non-executable rejection, got %v", err)
	}
}

func TestExecutorRejectsCLIReplacedAfterVerification(t *testing.T) {
	cli := multiCallCLI(t, 0o755)
	executor := multiCallExecutor(t, cli)
	if _, err := executor.Path(); err != nil {
		t.Fatal(err)
	}
	target, err := filepath.EvalSymlinks(cli)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = executor.Run(context.Background(), Request{Args: []string{"ps"}})
	if err == nil || !strings.Contains(err.Error(), "changed after verification") {
		t.Fatalf("expected replaced CLI rejection, got %v", err)
	}
}
