package capio

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestTailKeepsSmallOutputVerbatim(t *testing.T) {
	tail := NewTail(64)
	for _, chunk := range []string{"hello ", "world"} {
		if _, err := tail.Write([]byte(chunk)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if tail.Truncated() {
		t.Fatal("small output must not be marked truncated")
	}
	if got := tail.String(); got != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestTailBoundsRetainedBytesWithDeterministicMarker(t *testing.T) {
	// An in-memory fake process writes far more than the cap in uneven
	// chunks; only the last limit bytes survive behind a stable marker.
	const limit = 16
	var full bytes.Buffer
	tail := NewTail(limit)
	for i := 0; i < 100; i++ {
		chunk := []byte(fmt.Sprintf("chunk-%03d;", i))
		full.Write(chunk)
		if _, err := tail.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if !tail.Truncated() {
		t.Fatal("expected truncation")
	}
	marker := fmt.Sprintf("[vuelta: output truncated, kept last %d of %d bytes]\n", limit, full.Len())
	want := marker + string(full.Bytes()[full.Len()-limit:])
	if got := tail.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// The marker and tail must be reproducible across reads.
	if second := tail.String(); second != want {
		t.Fatalf("second read %q differs from first %q", second, want)
	}
}

func TestTailSingleWriteLargerThanLimit(t *testing.T) {
	tail := NewTail(4)
	if _, err := tail.Write([]byte("abcdefgh")); err != nil {
		t.Fatalf("write: %v", err)
	}
	want := "[vuelta: output truncated, kept last 4 of 8 bytes]\nefgh"
	if got := tail.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTailConcurrentWritersStayBounded(t *testing.T) {
	// Mimics separate stdout/stderr copier goroutines writing at once.
	const limit = 128
	tail := NewTail(limit)
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			line := []byte(fmt.Sprintf("writer-%d says something\n", id))
			for i := 0; i < 500; i++ {
				if _, err := tail.Write(line); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	got := tail.String()
	if len(got) > limit+len("[vuelta: output truncated, kept last 128 of 99999 bytes]\n") {
		t.Fatalf("retained output too large: %d bytes", len(got))
	}
	if !strings.HasPrefix(got, "[vuelta: output truncated, kept last 128 of ") {
		t.Fatalf("missing truncation marker: %q", got)
	}
}

func TestLimitKeepsSmallOutputAndDoesNotFire(t *testing.T) {
	fired := 0
	lim := NewLimit(32, func() { fired++ })
	if _, err := lim.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if lim.Exceeded() || fired != 0 {
		t.Fatalf("unexpected exceed: exceeded=%v fired=%d", lim.Exceeded(), fired)
	}
	if got := string(lim.Bytes()); got != `{"ok":true}` {
		t.Fatalf("got %q", got)
	}
}

func TestLimitFiresOnceAndDiscardsOverflow(t *testing.T) {
	fired := 0
	lim := NewLimit(8, func() { fired++ })
	for i := 0; i < 10; i++ {
		if _, err := lim.Write([]byte("abcde")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if !lim.Exceeded() {
		t.Fatal("expected exceeded")
	}
	if fired != 1 {
		t.Fatalf("onExceed fired %d times, want 1", fired)
	}
	if got := lim.Bytes(); len(got) != 8 || string(got) != "abcdeabc" {
		t.Fatalf("stored prefix %q, want %q", got, "abcdeabc")
	}
}

func TestLimitConcurrentWritersNoDeadlock(t *testing.T) {
	// onExceed cancelling a context must not deadlock against in-flight
	// writes from the other stream.
	done := make(chan struct{})
	var once sync.Once
	lim := NewLimit(64, func() { once.Do(func() { close(done) }) })
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if _, err := lim.Write([]byte("0123456789")); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case <-done:
	default:
		t.Fatal("onExceed never fired")
	}
	if len(lim.Bytes()) != 64 {
		t.Fatalf("stored %d bytes, want 64", len(lim.Bytes()))
	}
}
