package dockerexec

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestOrderedEndpoints(t *testing.T) {
	for _, mode := range []string{"both available", "first missing", "first stopped", "both stopped", "identity mismatch", "unsafe socket", "invalid identity", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			first, second := testEndpoint(), testEndpoint()
			second.SocketPath = "/approved/second.sock"
			second.Expected.ID = "second-daemon"
			approved := executable(t, 0o755)
			var probes, commands []string
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor := New(Options{
				Endpoints: []Endpoint{first, second},
				Resolver:  func(string) (string, error) { return approved, nil },
				EndpointValidator: func(endpoint Endpoint) (string, error) {
					if endpoint.SocketPath == first.SocketPath {
						if mode == "first missing" {
							return "", &EndpointUnavailableError{Err: errors.New("missing")}
						}
						if mode == "unsafe socket" {
							return "", errors.New("unsafe socket permissions")
						}
					}
					return endpoint.SocketPath, nil
				},
				CommandRunner: func(_ context.Context, _ string, request Request, _ []string) (Result, error) {
					host := request.Args[1]
					switch request.Args[2] {
					case "version":
						probes = append(probes, host)
						if mode == "cancelled" {
							cancel()
							return Result{}, context.Canceled
						}
						if mode == "both stopped" || (mode == "first stopped" && host == "unix://"+first.SocketPath) {
							return Result{}, errors.New("connection refused")
						}
						if mode == "invalid identity" {
							return Result{Stdout: []byte("invalid JSON")}, nil
						}
						return Result{Stdout: []byte(`{"server_version":"28.3.2","api_version":"1.49","os":"linux","architecture":"arm64"}`)}, nil
					case "info":
						id := first.Expected.ID
						if host == "unix://"+second.SocketPath {
							id = second.Expected.ID
						}
						if mode == "identity mismatch" {
							id = "impostor"
						}
						return Result{Stdout: []byte(`{"id":"` + id + `","security_options":["name=seccomp,profile=builtin"]}`)}, nil
					default:
						commands = append(commands, host)
						return Result{}, nil
					}
				},
			})
			_, err := executor.Run(ctx, Request{Args: []string{"ps"}})
			switch mode {
			case "both available", "first missing", "first stopped":
				if err != nil {
					t.Fatal(err)
				}
				want := first.SocketPath
				if mode != "both available" {
					want = second.SocketPath
				}
				if socket, err := executor.SocketPath(); err != nil || socket != want {
					t.Fatalf("socket = %s, %v", socket, err)
				}
				if _, err := executor.Run(ctx, Request{Args: []string{"ps"}}); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(commands, []string{"unix://" + want, "unix://" + want}) {
					t.Fatalf("commands = %v", commands)
				}
			case "both stopped":
				if err == nil || !strings.Contains(err.Error(), "no trusted Docker endpoint is available") || len(probes) != 2 {
					t.Fatalf("error = %v, probes = %v", err, probes)
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) || len(probes) != 1 {
					t.Fatalf("error = %v, probes = %v", err, probes)
				}
			default:
				if err == nil || len(commands) != 0 || len(probes) > 1 {
					t.Fatalf("error = %v, probes = %v, commands = %v", err, probes, commands)
				}
				if mode == "identity mismatch" {
					var attestation *AttestationError
					if !errors.As(err, &attestation) {
						t.Fatalf("expected attestation failure, got %v", err)
					}
				}
			}
		})
	}
}

func TestOrderedEndpointConcurrentSelection(t *testing.T) {
	approved := executable(t, 0o755)
	executor := New(Options{
		Endpoints:         []Endpoint{testEndpoint()},
		Resolver:          func(string) (string, error) { return approved, nil },
		EndpointValidator: testEndpointValidator,
		CommandRunner: func(_ context.Context, _ string, request Request, _ []string) (Result, error) {
			result, _ := daemonProbeResult(request)
			return result, nil
		},
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := executor.Run(context.Background(), Request{Args: []string{"ps"}}); err != nil {
				t.Error(err)
			}
			if _, err := executor.SocketPath(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}
