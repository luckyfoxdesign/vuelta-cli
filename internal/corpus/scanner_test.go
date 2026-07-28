package corpus

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEffectiveCaseTimeout(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
		wantErr    bool
	}{
		{name: "default", want: DefaultCaseTimeout},
		{name: "override", configured: 10 * time.Minute, want: 10 * time.Minute},
		{name: "negative", configured: -time.Second, wantErr: true},
		{name: "above maximum", configured: MaxCaseTimeout + time.Second, wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := EffectiveCaseTimeout(test.configured)
			if (err != nil) != test.wantErr {
				t.Fatalf("EffectiveCaseTimeout() error = %v, wantErr %t", err, test.wantErr)
			}
			if !test.wantErr && got != test.want {
				t.Fatalf("EffectiveCaseTimeout() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestProductionScannerAppliesOverrideToEveryPass(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	executable := filepath.Join(stateDir, "slow-vuelta")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec sleep 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(stateDir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	scanRoot := t.TempDir()
	scanner := &ProductionScanner{
		Executable: executable,
		configPath: filepath.Join(stateDir, "config.yaml"), stateDir: stateDir,
	}
	for pass := 1; pass <= 2; pass++ {
		_, err := scanner.Scan(context.Background(), ScanRequest{
			Directory: scanRoot, Timeout: 20 * time.Millisecond,
		})
		var timeoutErr *TimeoutError
		if !errors.Is(err, ErrTimeout) || !errors.As(err, &timeoutErr) {
			t.Fatalf("pass %d error = %v, want typed timeout", pass, err)
		}
		if timeoutErr.Duration != 20*time.Millisecond {
			t.Fatalf("pass %d timeout = %s", pass, timeoutErr.Duration)
		}
	}
}
