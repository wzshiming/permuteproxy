package testutils

import (
	"testing"
	"time"
)

// Wait receives from ch, failing the test if nothing arrives within 10 seconds.
func Wait[T any](t testing.TB, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}
