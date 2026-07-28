package corpus

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrTimeout classifies a bounded process deadline.
	ErrTimeout = errors.New("corpus process timed out")
	// ErrOutputTooLarge classifies structured output above the 5 MiB limit.
	ErrOutputTooLarge = errors.New("corpus process output exceeded limit")
	// ErrInvalidJSON classifies malformed or structurally invalid scanner JSON.
	ErrInvalidJSON = errors.New("corpus scanner returned invalid JSON")
)

// TimeoutError records the effective bound of a timed-out corpus process.
type TimeoutError struct {
	Duration time.Duration
}

// Error describes the bounded process timeout.
func (e *TimeoutError) Error() string {
	return fmt.Sprintf("corpus process exceeded timeout of %s", e.Duration)
}

// Unwrap preserves errors.Is(err, ErrTimeout) classification.
func (e *TimeoutError) Unwrap() error {
	return ErrTimeout
}
