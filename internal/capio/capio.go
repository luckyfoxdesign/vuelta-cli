// Package capio provides bounded collectors for untrusted subprocess output.
// Limits are enforced while the child is still streaming, so host memory
// stays bounded regardless of how much a process writes: Tail and Excerpt
// soft-truncate diagnostics, while Limit hard-stops structured output that
// must be parsed in full.
package capio

import (
	"fmt"
	"strings"
	"sync"
)

// Tail is an io.Writer retaining at most a fixed number of the most recently
// written bytes: the process keeps running (its lifetime is bounded by the
// caller's context/timeout) and a deterministic truncation marker is
// prepended when anything was dropped. It is safe for concurrent use by the
// separate stdout and stderr copier goroutines started by os/exec.
type Tail struct {
	mu    sync.Mutex
	limit int
	buf   []byte // ring storage, len(buf) grows up to limit
	next  int    // ring write position once buf is full
	total int64
}

// NewTail returns a Tail keeping the last limit bytes. limit must be positive.
func NewTail(limit int) *Tail {
	if limit <= 0 {
		panic("capio: tail limit must be positive")
	}
	return &Tail{limit: limit}
}

// Write never fails: excess bytes are discarded so the child can keep
// streaming until it exits or its context expires.
func (t *Tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	written := len(p)
	t.total += int64(written)
	if len(p) > t.limit {
		p = p[len(p)-t.limit:]
	}
	if t.buf == nil {
		t.buf = make([]byte, 0, t.limit)
	}
	if len(t.buf) < t.limit {
		grow := t.limit - len(t.buf)
		if grow > len(p) {
			grow = len(p)
		}
		t.buf = append(t.buf, p[:grow]...)
		p = p[grow:]
	}
	for len(p) > 0 {
		n := copy(t.buf[t.next:], p)
		t.next = (t.next + n) % t.limit
		p = p[n:]
	}
	return written, nil
}

// Truncated reports whether any bytes were dropped.
func (t *Tail) Truncated() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total > int64(t.limit)
}

// String returns the retained tail. When output was truncated the result is
// prefixed with a deterministic marker naming the total and retained sizes.
func (t *Tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total <= int64(t.limit) {
		return string(t.buf)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[vuelta: output truncated, kept last %d of %d bytes]\n", t.limit, t.total)
	b.Write(t.bytesLocked())
	return b.String()
}

func (t *Tail) bytesLocked() []byte {
	if t.total <= int64(t.limit) {
		return append([]byte(nil), t.buf...)
	}
	result := make([]byte, 0, len(t.buf))
	result = append(result, t.buf[t.next:]...)
	result = append(result, t.buf[:t.next]...)
	return result
}

// Excerpt retains deterministic first and last context under one fixed byte
// budget. It is intended for diagnostics where an initial error code and a
// final cause are both useful.
type Excerpt struct {
	mu        sync.Mutex
	limit     int
	headLimit int
	head      []byte
	tail      *Tail
	total     int64
}

// NewExcerpt returns an Excerpt retaining at most limit input bytes.
func NewExcerpt(limit int) *Excerpt {
	if limit <= 1 {
		panic("capio: excerpt limit must be greater than one")
	}
	headLimit := limit / 2
	return &Excerpt{
		limit: limit, headLimit: headLimit,
		tail: NewTail(limit - headLimit),
	}
}

// Write never fails and never retains more than the configured byte budget.
func (e *Excerpt) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	written := len(p)
	e.total += int64(written)
	if len(e.head) < e.headLimit {
		keep := e.headLimit - len(e.head)
		if keep > len(p) {
			keep = len(p)
		}
		e.head = append(e.head, p[:keep]...)
		p = p[keep:]
	}
	if len(p) > 0 {
		_, _ = e.tail.Write(p)
	}
	return written, nil
}

// String returns the complete small output or a marked first/last excerpt.
func (e *Excerpt) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tail.mu.Lock()
	defer e.tail.mu.Unlock()
	tail := e.tail.bytesLocked()
	if e.total <= int64(e.limit) {
		return string(append(append([]byte(nil), e.head...), tail...))
	}
	var b strings.Builder
	b.Write(e.head)
	fmt.Fprintf(&b, "\n[vuelta: output truncated, kept first %d and last %d of %d bytes]\n",
		e.headLimit, e.limit-e.headLimit, e.total)
	b.Write(tail)
	return b.String()
}

// Limit is an io.Writer storing at most limit bytes, for structured output
// that must be parsed in full: on overflow the caller fails closed instead of
// parsing a truncated document. The first write that would exceed the limit
// invokes onExceed exactly once (typically the cancel function of the
// subprocess context, so exec.CommandContext kills the process); every byte
// past the limit is discarded so the copier goroutine keeps draining the pipe
// while the process dies.
type Limit struct {
	mu       sync.Mutex
	limit    int
	buf      []byte
	exceeded bool
	onExceed func()
}

// NewLimit returns a Limit enforcing limit bytes. limit must be positive;
// onExceed may be nil.
func NewLimit(limit int, onExceed func()) *Limit {
	if limit <= 0 {
		panic("capio: hard limit must be positive")
	}
	return &Limit{limit: limit, onExceed: onExceed}
}

// Write never returns an error; overflow is signalled through onExceed and
// Exceeded so callers can fail closed deterministically after the run.
func (l *Limit) Write(p []byte) (int, error) {
	l.mu.Lock()
	written := len(p)
	room := l.limit - len(l.buf)
	if room > len(p) {
		room = len(p)
	}
	if room > 0 {
		l.buf = append(l.buf, p[:room]...)
	}
	fire := false
	if written > room && !l.exceeded {
		l.exceeded = true
		fire = l.onExceed != nil
	}
	l.mu.Unlock()
	if fire {
		l.onExceed()
	}
	return written, nil
}

// Exceeded reports whether the hard limit was crossed. Callers must treat the
// stored bytes as incomplete and fail the operation when it returns true.
func (l *Limit) Exceeded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.exceeded
}

// Bytes returns the stored prefix (at most the configured limit).
func (l *Limit) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf...)
}
