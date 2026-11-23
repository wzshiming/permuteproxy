package testutils

import (
	"fmt"
	"runtime"
	"testing"
	"testing/synctest"
)

func TestWaitReturnsTheValueSent(t *testing.T) {
	ch := make(chan int, 1)
	ch <- 7
	if got := Wait(t, ch, "the value"); got != 7 {
		t.Fatalf("Wait = %d, want 7", got)
	}
}

// fatalRecorder keeps the message of Fatalf and ends the goroutine, as testing.T does.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestWaitFailsWhenNothingArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &fatalRecorder{TB: t}
		done := make(chan struct{})
		go func() {
			defer close(done)
			Wait(r, make(chan int), "the value")
		}()
		<-done
		if want := "timed out waiting for the value"; r.msg != want {
			t.Fatalf("Wait failed with %q, want %q", r.msg, want)
		}
	})
}
