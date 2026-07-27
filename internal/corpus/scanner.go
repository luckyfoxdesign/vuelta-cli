package corpus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/capio"
)

const (
	scanTimeout       = 5 * time.Minute
	scanOutputLimit   = 5 << 20
	scanStderrLimit   = 64 << 10
	preflightTimeout  = 2 * time.Minute
	preflightOutLimit = 1 << 20
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

// ScanRequest describes one production Vuelta scan.
type ScanRequest struct {
	Directory string
	Args      []string
}

// ProcessObservation is bounded stdout/stderr plus process status.
type ProcessObservation struct {
	Stdout    []byte
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// Scanner is the process boundary used by Harness.
type Scanner interface {
	Preflight(context.Context, string) (Environment, error)
	Scan(context.Context, ScanRequest) (ProcessObservation, error)
}

// ProductionScanner runs the just-built production Vuelta CLI with an
// isolated machine config and a minimal environment.
type ProductionScanner struct {
	Executable   string
	SourceRoot   string
	DockerSocket string
	configPath   string
	stateDir     string
}

// Preflight probes and trusts the explicit Docker endpoint once for the run.
func (s *ProductionScanner) Preflight(ctx context.Context, runDir string) (Environment, error) {
	s.stateDir = filepath.Join(runDir, ".state")
	if err := os.Mkdir(s.stateDir, 0o700); err != nil {
		return Environment{}, fmt.Errorf("create isolated scanner state: %w", err)
	}
	if s.Executable == "" {
		s.Executable = filepath.Join(s.stateDir, "vuelta")
		if err := BuildProductionVuelta(ctx, s.SourceRoot, s.Executable, s.stateDir); err != nil {
			return Environment{}, err
		}
	}
	if !filepath.IsAbs(s.Executable) || !filepath.IsAbs(s.DockerSocket) {
		return Environment{}, errors.New("scanner executable and Docker socket must be absolute")
	}
	info, err := os.Stat(s.Executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return Environment{}, errors.New("production Vuelta executable is unavailable")
	}
	s.configPath = filepath.Join(s.stateDir, "config.yaml")
	home := filepath.Join(s.stateDir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return Environment{}, fmt.Errorf("create isolated scanner home: %w", err)
	}
	args := []string{
		"--no-input", "environment", "bootstrap", "--socket", s.DockerSocket,
		"--yes", "--json", s.configPath,
	}
	observation, runErr := s.run(ctx, home, preflightTimeout, preflightOutLimit, args)
	if runErr != nil {
		return Environment{}, fmt.Errorf("vuelta environment preflight: %w", runErr)
	}
	if observation.ExitCode != 0 {
		return Environment{}, fmt.Errorf("vuelta environment preflight exited %d: %s", observation.ExitCode, SanitizeMessage(observation.Stderr))
	}
	var envelope struct {
		Format  int    `json:"format"`
		Command string `json:"command"`
		Results []struct {
			Status string `json:"status"`
			Daemon struct {
				ServerVersion   string `json:"server_version"`
				OperatingSystem string `json:"operating_system"`
				Architecture    string `json:"architecture"`
			} `json:"daemon"`
		} `json:"results"`
	}
	if err := json.Unmarshal(observation.Stdout, &envelope); err != nil ||
		envelope.Format != 1 || envelope.Command != "environment bootstrap" ||
		len(envelope.Results) != 1 || envelope.Results[0].Status != "trusted" {
		return Environment{}, errors.New("vuelta environment preflight returned an invalid envelope")
	}
	if err := s.probeDockerNetwork(ctx, home); err != nil {
		return Environment{}, err
	}
	return Environment{
		DockerOS:      envelope.Results[0].Daemon.OperatingSystem,
		Architecture:  envelope.Results[0].Daemon.Architecture,
		ServerVersion: envelope.Results[0].Daemon.ServerVersion,
		Scanner:       filepath.Base(s.Executable),
	}, nil
}

func (s *ProductionScanner) probeDockerNetwork(ctx context.Context, home string) error {
	digest := sha256.Sum256([]byte(s.stateDir))
	name := fmt.Sprintf("vuelta-corpus-preflight-%x", digest[:6])
	endpoint := "unix://" + s.DockerSocket
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stderr := capio.NewTail(scanStderrLimit)
	command := exec.CommandContext(
		probeCtx,
		"docker",
		"--host", endpoint,
		"network", "create",
		"--internal",
		"--label", "io.vuelta.owner=corpus-preflight",
		name,
	)
	command.Env = minimalScannerEnvironment(home, s.stateDir)
	command.Stdout = io.Discard
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("docker scanner network preflight failed: %s", SanitizeMessage(stderr.String()))
	}
	removeCtx, removeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer removeCancel()
	removeStderr := capio.NewTail(scanStderrLimit)
	remove := exec.CommandContext(removeCtx, "docker", "--host", endpoint, "network", "rm", name)
	remove.Env = minimalScannerEnvironment(home, s.stateDir)
	remove.Stdout = io.Discard
	remove.Stderr = removeStderr
	if err := remove.Run(); err != nil {
		return fmt.Errorf("remove owned docker scanner preflight network: %s", SanitizeMessage(removeStderr.String()))
	}
	return nil
}

// Scan runs one bounded, non-interactive production scan.
func (s *ProductionScanner) Scan(ctx context.Context, request ScanRequest) (ProcessObservation, error) {
	if s.configPath == "" || s.stateDir == "" {
		return ProcessObservation{}, errors.New("scanner preflight has not completed")
	}
	if !filepath.IsAbs(request.Directory) {
		return ProcessObservation{}, errors.New("scan directory must be absolute")
	}
	args := []string{"--config", s.configPath, "--no-input", "--no-color", "scan", "--directory", request.Directory}
	args = append(args, request.Args...)
	args = append(args, "--json")
	return s.run(ctx, filepath.Join(s.stateDir, "home"), scanTimeout, scanOutputLimit, args)
}

func (s *ProductionScanner) run(ctx context.Context, home string, timeout time.Duration, outputLimit int, args []string) (ProcessObservation, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := capio.NewLimit(outputLimit, cancel)
	stderr := capio.NewTail(scanStderrLimit)
	command := exec.CommandContext(runCtx, s.Executable, args...)
	command.Env = minimalScannerEnvironment(home, s.stateDir)
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 10 * time.Second
	started := time.Now()
	err := command.Run()
	observation := ProcessObservation{
		Stdout: stdout.Bytes(), Stderr: sanitizeLog(stderr.String()),
		Duration: time.Since(started), Truncated: stderr.Truncated(),
	}
	if stdout.Exceeded() {
		return observation, ErrOutputTooLarge
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return observation, ErrTimeout
	}
	if err == nil {
		return observation, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		observation.ExitCode = exitErr.ExitCode()
		return observation, nil
	}
	return observation, fmt.Errorf("execute production Vuelta scan: %w", err)
}

func minimalScannerEnvironment(home, temp string) []string {
	values := []string{
		"HOME=" + home,
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin:/usr/local/bin",
		"TMPDIR=" + temp,
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
	}
	sort.Strings(values)
	return values
}

func sanitizeLog(value string) string {
	value = ansiPattern.ReplaceAllString(value, "")
	value = strings.ToValidUTF8(value, "\uFFFD")
	var output bytes.Buffer
	for _, current := range value {
		switch {
		case current == '\n' || current == '\t':
			output.WriteRune(current)
		case current >= 0x20 && current != 0x7f:
			output.WriteRune(current)
		}
	}
	return output.String()
}
