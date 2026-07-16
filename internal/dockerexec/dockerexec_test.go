package dockerexec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
		CommandRunner: func(_ context.Context, path string, _ Request, env []string) (Result, error) {
			paths = append(paths, path)
			environments = append(environments, append([]string(nil), env...))
			return Result{}, nil
		},
	})

	for name, value := range map[string]string{
		"PATH": "/hostile/bin", "DOCKER_HOST": "tcp://attacker.invalid:2375",
		"DOCKER_CONTEXT": "hostile", "DOCKER_CONFIG": "/hostile/config",
		"HTTP_PROXY": "http://attacker.invalid", "HTTPS_PROXY": "http://attacker.invalid",
		"ALL_PROXY": "socks5://attacker.invalid", "HOME": "/hostile/home",
	} {
		t.Setenv(name, value)
	}

	request := Request{Args: []string{"version"}, Env: map[string]string{"VUELTA_IMAGE": "registry.example/app@sha256:abc"}}
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
	if !reflect.DeepEqual(paths, []string{absolute, absolute}) {
		t.Fatalf("command paths = %#v, want exact absolute path %q", paths, absolute)
	}
	wantEnv := []string{"DOCKER_CONFIG=" + configDir, "VUELTA_IMAGE=registry.example/app@sha256:abc"}
	for _, got := range environments {
		if !reflect.DeepEqual(got, wantEnv) {
			t.Fatalf("child environment = %#v, want %#v", got, wantEnv)
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
	})
	_, err := executor.Run(context.Background(), Request{
		Args: []string{"version"}, Env: map[string]string{"DOCKER_HOST": "tcp://attacker.invalid:2375"},
	})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected environment rejection, got %v", err)
	}
}

func TestExecutorRejectsGroupWritableBinary(t *testing.T) {
	executor := New(Options{
		Resolver:  func(string) (string, error) { return executable(t, 0o775), nil },
		ConfigDir: filepath.Join(t.TempDir(), "docker-config"),
	})
	if _, err := executor.Path(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected writable binary rejection, got %v", err)
	}
}
