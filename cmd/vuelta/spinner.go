package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const spinnerInterval = 100 * time.Millisecond
const scanElapsedThreshold = 3 * time.Second

// scanProgress reports phase labels for long-running scan stages (Docker
// pull/build, container-based scans). When animated it draws an
// indeterminate spinner on stderr in place; otherwise it prints one plain
// line per phase, identical to scan's historical non-tty output.
type scanProgress struct {
	animated bool
	stderr   io.Writer
	cancel   chan struct{}
	finished chan struct{}
}

func newScanProgress(animated bool, stderr io.Writer) *scanProgress {
	return &scanProgress{animated: animated, stderr: stderr}
}

// scanProgressEligible reports whether stderr is an interactive terminal
// eligible for spinner animation, honoring --no-color, --json, NO_COLOR, and
// TERM=dumb the same way cli.go's terminalOutput gates color and animation.
func scanProgressEligible(options scanOptions) bool {
	if options.noColor || options.jsonOutput {
		return false
	}
	if !isTerminal(os.Stderr) {
		return false
	}
	if _, noColorEnvironment := os.LookupEnv("NO_COLOR"); noColorEnvironment {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

// start begins (or, if animated, replaces) the phase display for message.
// Call stop once the phase completes, whether it succeeded or failed.
func (p *scanProgress) start(message string) {
	if !p.animated {
		_, _ = fmt.Fprintln(p.stderr, message)
		return
	}
	if p.cancel != nil {
		p.stop()
	}
	cancel := make(chan struct{})
	finished := make(chan struct{})
	p.cancel = cancel
	p.finished = finished
	stderr := p.stderr
	go func() {
		defer close(finished)
		ticker := time.NewTicker(spinnerInterval)
		defer ticker.Stop()
		started := time.Now()
		frame := 0
		_, _ = fmt.Fprint(stderr, scanProgressFrame(spinnerFrames[frame], message, 0))
		for {
			select {
			case <-cancel:
				return
			case <-ticker.C:
				frame = (frame + 1) % len(spinnerFrames)
				_, _ = fmt.Fprint(stderr, scanProgressFrame(spinnerFrames[frame], message, time.Since(started)))
			}
		}
	}()
}

func scanProgressFrame(frame, message string, elapsed time.Duration) string {
	// Reserve the initial elapsed suffix width so the line does not jump when
	// the timer first appears. The spaces remain invisible for short phases.
	suffix := "     "
	if elapsed >= scanElapsedThreshold {
		suffix = fmt.Sprintf(" — %ds", int64(elapsed/time.Second))
	}
	return fmt.Sprintf("\r%s %s%s", frame, message, suffix)
}

// stop ends the current animated phase, if any, and clears its line. It is
// always safe to call, including when start was never called for this phase.
func (p *scanProgress) stop() {
	if !p.animated || p.cancel == nil {
		return
	}
	close(p.cancel)
	<-p.finished
	_, _ = fmt.Fprint(p.stderr, "\r\x1b[2K")
	p.cancel = nil
	p.finished = nil
}
