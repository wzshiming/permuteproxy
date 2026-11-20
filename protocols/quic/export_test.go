package quic

import (
	"testing"
	"time"
)

// SetIdleTimeout gives the connections built during t an idle timeout of d.
func SetIdleTimeout(t testing.TB, d time.Duration) {
	old := maxIdle
	maxIdle = d
	t.Cleanup(func() { maxIdle = old })
}
