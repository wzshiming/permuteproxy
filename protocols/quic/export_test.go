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

// SetLinger bounds by d how long the dialed conns closed during t keep their connections.
func SetLinger(t testing.TB, d time.Duration) {
	old := linger
	linger = d
	t.Cleanup(func() { linger = old })
}

// SetCloseWait bounds by d how long the Close of a dialed conn waits for its release during t.
func SetCloseWait(t testing.TB, d time.Duration) {
	old := closeWait
	closeWait = d
	t.Cleanup(func() { closeWait = old })
}

// SetOpenWait bounds by d how long the dials during t wait for a stream of a shared connection.
func SetOpenWait(t testing.TB, d time.Duration) {
	old := openWait
	openWait = d
	t.Cleanup(func() { openWait = old })
}

// MaxStreams is how many conns share one connection.
const MaxStreams = maxStreams
