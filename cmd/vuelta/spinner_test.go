package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestScanProgressEligibleRespectsNoColorAndJSON(t *testing.T) {
	if scanProgressEligible(scanOptions{noColor: true}) {
		t.Fatal("--no-color must disable spinner eligibility regardless of the terminal")
	}
	if scanProgressEligible(scanOptions{jsonOutput: true}) {
		t.Fatal("--json must disable spinner eligibility regardless of the terminal")
	}
}

func TestScanProgressNonAnimatedPrintsPlainLine(t *testing.T) {
	var buf bytes.Buffer
	progress := newScanProgress(false, &buf)
	progress.start("Scanning packages for updates...")
	progress.update("Packages 1/2: npm")
	progress.stop()
	if buf.String() != "Scanning packages for updates...\nPackages 1/2: npm\n" {
		t.Fatalf("non-animated output = %q, want one plain line per update", buf.String())
	}
	if strings.ContainsAny(buf.String(), "\r\x1b") {
		t.Fatalf("non-animated output must contain no control characters: %q", buf.String())
	}
}

func TestScanProgressNonAnimatedStopWithoutStartIsSafe(t *testing.T) {
	var buf bytes.Buffer
	progress := newScanProgress(false, &buf)
	progress.stop()
	if buf.Len() != 0 {
		t.Fatalf("stop without start must not write anything, got %q", buf.String())
	}
}

func TestScanProgressAnimatedStartAndStopIsBoundedAndClears(t *testing.T) {
	var buf bytes.Buffer
	progress := newScanProgress(true, &buf)
	progress.start("Preparing scanner for the first run...")
	cancel := progress.cancel
	finished := progress.finished
	progress.update("Packages 1/2: npm")
	if progress.cancel != cancel || progress.finished != finished {
		t.Fatal("update restarted the spinner goroutine")
	}
	if progress.currentMessage() != "Packages 1/2: npm" {
		t.Fatalf("active message = %q, want updated message", progress.currentMessage())
	}
	progress.stop()
	output := buf.String()
	if !strings.Contains(output, "Preparing scanner for the first run...") {
		t.Fatalf("animated output missing the phase message: %q", output)
	}
	if !strings.HasSuffix(output, "\r\x1b[2K") {
		t.Fatalf("animated output must end by clearing its line: %q", output)
	}
	// stop must be idempotent and safe once the phase already ended.
	progress.stop()
}

func TestScanProgressAnimatedUpdateClearsLongerPreviousMessage(t *testing.T) {
	var buf bytes.Buffer
	progress := newScanProgress(true, &buf)
	progress.start("Images 10/10: registry.example/very-long-image:latest (linux/amd64)")
	progress.update("Images 1/1: app")
	if progress.currentMessage() != "Images 1/1: app" {
		t.Fatalf("active message = %q, want shorter updated message", progress.currentMessage())
	}
	progress.stop()

	frame := scanProgressFrame("⠙", "Images 1/1: app", 0)
	if !strings.HasPrefix(frame, "\r\x1b[2K") {
		t.Fatalf("updated frame does not clear the previous line: %q", frame)
	}
}

func TestScanProgressConcurrentUpdateAndRender(t *testing.T) {
	progress := newScanProgress(true, io.Discard)
	progress.start("Scanning images...")
	deadline := time.Now().Add(3 * spinnerInterval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for time.Now().Before(deadline) {
			progress.update("Images 1/2: app (linux/amd64)")
			progress.update("Images 2/2: app (linux/arm64)")
		}
	}()
	<-done
	progress.stop()
}

func TestScanProgressFrameShowsElapsedOnlyAfterThreshold(t *testing.T) {
	before := scanProgressFrame("⠋", "Scanning dependencies with trivy...", scanElapsedThreshold-time.Millisecond)
	if strings.Contains(before, " — ") {
		t.Fatalf("elapsed appeared before threshold: %q", before)
	}
	atThreshold := scanProgressFrame("⠙", "Scanning dependencies with trivy...", scanElapsedThreshold)
	if !strings.HasSuffix(atThreshold, " — 3s") {
		t.Fatalf("elapsed frame = %q, want 3s suffix", atThreshold)
	}
	later := scanProgressFrame("⠹", "Scanning dependencies with trivy...", 47*time.Second)
	if !strings.HasSuffix(later, " — 47s") {
		t.Fatalf("elapsed frame = %q, want 47s suffix", later)
	}
}
