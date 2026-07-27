package corpus

import "errors"

var (
	// ErrTimeout classifies a bounded process deadline.
	ErrTimeout = errors.New("corpus process timed out")
	// ErrOutputTooLarge classifies structured output above the 5 MiB limit.
	ErrOutputTooLarge = errors.New("corpus process output exceeded limit")
	// ErrInvalidJSON classifies malformed or structurally invalid scanner JSON.
	ErrInvalidJSON = errors.New("corpus scanner returned invalid JSON")
)
