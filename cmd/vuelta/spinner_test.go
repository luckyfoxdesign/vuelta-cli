package main

import (
	"bytes"
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
	progress.stop()
	if buf.String() != "Scanning packages for updates...\n" {
		t.Fatalf("non-animated output = %q, want a single plain line", buf.String())
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
