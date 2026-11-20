package quic_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
)

// connected dials ln through tr and returns both ends of the stream.
func connected(t *testing.T, ln net.Listener, tr permuteproxy.Transport) (c, srv net.Conn) {
	t.Helper()
	accepted := accept(t, ln)
	c = dial(t, tr)
	return c, recv(t, accepted, "accept")
}

func assertTimeout(t *testing.T, err error, what string) {
	t.Helper()
	var ne net.Error
	if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("%s = %v, want a timeout matching os.ErrDeadlineExceeded", what, err)
	}
}

func setDeadline(t *testing.T, set func(time.Time) error, at time.Time) {
	t.Helper()
	if err := set(at); err != nil {
		t.Fatal(err)
	}
}

// within fails unless f returns in [min, max).
func within(t *testing.T, min, max time.Duration, what string, f func()) {
	t.Helper()
	start := time.Now()
	f()
	if d := time.Since(start); d < min || d >= max {
		t.Fatalf("%s took %v, want [%v, %v)", what, d, min, max)
	}
}

func TestReadDeadline(t *testing.T) {
	overCarriers(t, func(t *testing.T, e permuteproxy.Engine) {
		ln, tr := pair(t, e)
		c, srv := connected(t, ln, tr)
		b := make([]byte, 1)

		setDeadline(t, c.SetReadDeadline, time.Now().Add(-time.Second))
		within(t, 0, time.Second, "Read past its deadline", func() {
			_, err := c.Read(b)
			assertTimeout(t, err, "Read past its deadline")
		})

		setDeadline(t, c.SetReadDeadline, time.Now().Add(200*time.Millisecond))
		within(t, 150*time.Millisecond, 3*time.Second, "Read until its deadline", func() {
			_, err := c.Read(b)
			assertTimeout(t, err, "Read until its deadline")
		})

		setDeadline(t, c.SetReadDeadline, time.Time{})
		time.AfterFunc(200*time.Millisecond, func() { srv.Write([]byte("x")) })
		if _, err := c.Read(b); err != nil {
			t.Fatalf("Read once its deadline is cleared = %v", err)
		}

		time.AfterFunc(200*time.Millisecond, func() { c.SetReadDeadline(time.Now()) })
		within(t, 150*time.Millisecond, 3*time.Second, "Read until a deadline set while it blocks", func() {
			_, err := c.Read(b)
			assertTimeout(t, err, "Read until a deadline set while it blocks")
		})

		setDeadline(t, c.SetReadDeadline, time.Now().Add(100*time.Millisecond))
		setDeadline(t, c.SetReadDeadline, time.Time{})
		time.AfterFunc(400*time.Millisecond, func() { srv.Write([]byte("y")) })
		if _, err := c.Read(b); err != nil || b[0] != 'y' {
			t.Fatalf("Read past a cleared deadline = %q, %v; want y", b, err)
		}
	})
}

func TestWriteDeadline(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	c, srv := connected(t, ln, tr)

	setDeadline(t, c.SetWriteDeadline, time.Now().Add(-time.Second))
	_, err := c.Write([]byte("x"))
	assertTimeout(t, err, "Write past its deadline")

	// The listener reads nothing, so flow control stops the Write.
	data := make([]byte, 8<<20)
	setDeadline(t, c.SetWriteDeadline, time.Now().Add(300*time.Millisecond))
	within(t, 250*time.Millisecond, 3*time.Second, "Write until its deadline", func() {
		n, err := c.Write(data)
		assertTimeout(t, err, "Write until its deadline")
		if n >= len(data) {
			t.Fatalf("Write wrote %d of %d bytes before its deadline", n, len(data))
		}
	})

	setDeadline(t, c.SetWriteDeadline, time.Time{})
	go io.Copy(io.Discard, srv)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("Write once its deadline is cleared = %v", err)
	}
}

func TestSetDeadlineCoversBothDirections(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	c, _ := connected(t, ln, tr)
	setDeadline(t, c.SetDeadline, time.Now().Add(-time.Second))
	_, err := c.Read(make([]byte, 1))
	assertTimeout(t, err, "Read past the deadline")
	_, err = c.Write([]byte("x"))
	assertTimeout(t, err, "Write past the deadline")
}

// quicGoroutines are the stacks of the goroutines running x/net/quic, its TLS handshakes or this package.
func quicGoroutines() []string {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	var found []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "golang.org/x/net/quic.") || strings.Contains(g, "crypto/tls.(*QUICConn)") || strings.Contains(g, "permuteproxy/protocols/quic.") {
			found = append(found, g)
		}
	}
	return found
}

// noGoroutinesLeft fails unless the goroutines quicGoroutines lists are gone within a second.
func noGoroutinesLeft(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		left := quicGoroutines()
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines left:\n\n%s", len(left), strings.Join(left, "\n\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func signaled(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: timed out", what)
	}
}

// ends dials ln through tr and returns the end of the stream side names, then the other.
func ends(t *testing.T, ln net.Listener, tr permuteproxy.Transport, side string) (end, peer net.Conn) {
	t.Helper()
	c, srv := connected(t, ln, tr)
	if side == "accepted" {
		return srv, c
	}
	return c, srv
}

func TestCloseInterruptsABlockedRead(t *testing.T) {
	overCarriers(t, func(t *testing.T, e permuteproxy.Engine) {
		ln, tr := pair(t, e)
		for _, side := range []string{"dialed", "accepted"} {
			end, _ := ends(t, ln, tr, side)
			errc := make(chan error, 1)
			go func() {
				_, err := end.Read(make([]byte, 1))
				errc <- err
			}()
			time.Sleep(100 * time.Millisecond)
			start := time.Now()
			end.Close()
			if err := recv(t, errc, side+" Read"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s Read blocked at Close = %v, want net.ErrClosed", side, err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("%s Read returned %v after Close", side, d)
			}
		}
	})
}

func TestCloseInterruptsABlockedWrite(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	for _, side := range []string{"dialed", "accepted"} {
		end, peer := ends(t, ln, tr, side)
		errc := make(chan error, 1)
		go func() {
			// The peer reads nothing, so flow control stops the Write.
			_, err := end.Write(make([]byte, 8<<20))
			errc <- err
		}()
		time.Sleep(200 * time.Millisecond)
		start := time.Now()
		closed := make(chan struct{})
		go func() {
			end.Close()
			close(closed)
		}()
		if err := recv(t, errc, side+" Write"); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s Write blocked at Close = %v, want net.ErrClosed", side, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("%s Write returned %v after Close", side, d)
		}
		// The peer refusing the rest ends the wait of a dialed end for its acknowledgement.
		peer.Close()
		signaled(t, closed, side+" Close")
	}
}

// released fails unless s was closed once and nothing reads or writes it any more.
func released(t *testing.T, s *memSocket, what string) {
	t.Helper()
	if c, a := s.closes.Load(), s.active.Load(); c != 1 || a != 0 {
		t.Fatalf("%s carrier closed %d times with %d calls in flight, want once with none", what, c, a)
	}
}

func TestCloseReleasesEverythingOnce(t *testing.T) {
	noGoroutinesLeft(t)
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, srv := connected(t, ln, tr)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(srv, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	released(t, mem.socket(t, 1), "dialed")
	srv.Close()
	for range 2 {
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
	}
	released(t, mem.socket(t, 0), "listened")
	noGoroutinesLeft(t)
}

func TestCancelingADialInItsHandshakeReleasesEverything(t *testing.T) {
	noGoroutinesLeft(t)
	mem := newMemNet()
	// Nothing listens at the endpoint, so the handshake waits.
	tr := build(t, permuteproxy.Engine{Base: mem}, quicChain("127.0.0.1:9", issue(t).client))
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := tr.Dial(ctx, permuteproxy.Stream)
		errc <- err
	}()
	signaled(t, mem.sent, "the first handshake datagram")
	start := time.Now()
	cancel()
	if err := recv(t, errc, "Dial"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Dial returned %v after its cancel", d)
	}
	released(t, mem.socket(t, 0), "dialed")
	noGoroutinesLeft(t)
}

func TestCloseGivesUpOnAPeerThatNeverAcknowledges(t *testing.T) {
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, _ := connected(t, ln, tr)
	mem.cut()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	within(t, 4*time.Second, 8*time.Second, "Close", func() { c.Close() })
}

func TestCloseWaitsNoLongerThanTheWriteDeadline(t *testing.T) {
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, _ := connected(t, ln, tr)
	mem.cut()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	setDeadline(t, c.SetWriteDeadline, time.Now().Add(300*time.Millisecond))
	within(t, 0, 2*time.Second, "Close", func() { c.Close() })
}
