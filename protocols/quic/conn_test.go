package quic_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols/quic"
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

// notBefore fails unless f returns at or after at, and before max has passed since.
func notBefore(t *testing.T, at time.Time, max time.Duration, what string, f func()) {
	t.Helper()
	f()
	if d := time.Since(at); d < 0 || d >= max {
		t.Fatalf("%s returned %v after its deadline, want [0, %v)", what, d, max)
	}
}

func TestReadDeadline(t *testing.T) {
	overCarriers(t, func(t *testing.T, e permuteproxy.Engine) {
		ln, tr := pair(t, e)
		for _, side := range []string{"dialed", "accepted"} {
			c, peer := ends(t, ln, tr, side)
			b := make([]byte, 1)

			setDeadline(t, c.SetReadDeadline, time.Now().Add(-time.Second))
			within(t, 0, time.Second, side+" Read past its deadline", func() {
				_, err := c.Read(b)
				assertTimeout(t, err, side+" Read past its deadline")
			})

			at := time.Now().Add(200 * time.Millisecond)
			setDeadline(t, c.SetReadDeadline, at)
			notBefore(t, at, 3*time.Second, side+" Read until its deadline", func() {
				_, err := c.Read(b)
				assertTimeout(t, err, side+" Read until its deadline")
			})

			setDeadline(t, c.SetReadDeadline, time.Time{})
			time.AfterFunc(200*time.Millisecond, func() { peer.Write([]byte("x")) })
			if _, err := c.Read(b); err != nil {
				t.Fatalf("%s Read once its deadline is cleared = %v", side, err)
			}

			at = time.Now().Add(200 * time.Millisecond)
			time.AfterFunc(time.Until(at), func() { c.SetReadDeadline(at) })
			notBefore(t, at, 3*time.Second, side+" Read until a deadline set while it blocks", func() {
				_, err := c.Read(b)
				assertTimeout(t, err, side+" Read until a deadline set while it blocks")
			})

			setDeadline(t, c.SetReadDeadline, time.Now().Add(100*time.Millisecond))
			setDeadline(t, c.SetReadDeadline, time.Time{})
			time.AfterFunc(400*time.Millisecond, func() { peer.Write([]byte("y")) })
			if _, err := c.Read(b); err != nil || b[0] != 'y' {
				t.Fatalf("%s Read past a cleared deadline = %q, %v; want y", side, b, err)
			}
		}
	})
}

func TestWriteDeadline(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	for _, side := range []string{"dialed", "accepted"} {
		c, peer := ends(t, ln, tr, side)

		setDeadline(t, c.SetWriteDeadline, time.Now().Add(-time.Second))
		_, err := c.Write([]byte("x"))
		assertTimeout(t, err, side+" Write past its deadline")

		// The peer reads nothing, so flow control stops the Write.
		data := make([]byte, 8<<20)
		at := time.Now().Add(300 * time.Millisecond)
		setDeadline(t, c.SetWriteDeadline, at)
		notBefore(t, at, 3*time.Second, side+" Write until its deadline", func() {
			n, err := c.Write(data)
			assertTimeout(t, err, side+" Write until its deadline")
			if n >= len(data) {
				t.Fatalf("%s Write wrote %d of %d bytes before its deadline", side, n, len(data))
			}
		})

		setDeadline(t, c.SetWriteDeadline, time.Time{})
		go io.Copy(io.Discard, peer)
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("%s Write once its deadline is cleared = %v", side, err)
		}
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

// quicGoroutines are the stacks of the goroutines running x/net/quic, its TLS handshakes or this package, by goroutine.
func quicGoroutines() map[string]string {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	found := map[string]string{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "golang.org/x/net/quic.") || strings.Contains(g, "crypto/tls.(*QUICConn)") || strings.Contains(g, "permuteproxy/protocols/quic.") {
			id, _, _ := strings.Cut(g, " [")
			found[id] = g
		}
	}
	return found
}

// noGoroutinesLeft fails unless the quicGoroutines missing from before end within wait.
func noGoroutinesLeft(t *testing.T, before map[string]string, wait time.Duration) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		var left []string
		for id, g := range quicGoroutines() {
			if _, ok := before[id]; !ok {
				left = append(left, g)
			}
		}
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
		signaled(t, closed, side+" Close")
		peer.Close()
	}
}

// released fails unless s was closed once and nothing reads or writes it any more.
func released(t *testing.T, s *memSocket, what string) {
	t.Helper()
	if c, a := s.closes.Load(), s.active.Load(); c != 1 || a != 0 {
		t.Fatalf("%s carrier closed %d times with %d calls in flight, want once with none", what, c, a)
	}
}

// eventuallyReleased fails unless s is released, as released checks, within wait.
func eventuallyReleased(t *testing.T, s *memSocket, wait time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for (s.closes.Load() == 0 || s.active.Load() != 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	released(t, s, what)
}

func TestCloseReleasesEverythingOnce(t *testing.T) {
	before := quicGoroutines()
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
	srv.Close()
	eventuallyReleased(t, mem.socket(t, 1), 5*time.Second, "dialed")
	for range 2 {
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
	}
	released(t, mem.socket(t, 0), "listened")
	noGoroutinesLeft(t, before, time.Second)
}

func TestCancelingADialInItsHandshakeReleasesEverything(t *testing.T) {
	before := quicGoroutines()
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
	noGoroutinesLeft(t, before, time.Second)
}

// writeAndClose dials tr, writes msg and closes the conn without reading.
func writeAndClose(tr permuteproxy.Transport, msg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil && strings.Contains(err.Error(), "handshake timeout") {
		// x/net/quic stalls about one handshake in 3000 over udp loopback.
		c, err = tr.Dial(ctx, permuteproxy.Stream)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(msg))
	return err
}

func TestEveryStreamWrittenAndClosedArrivesWhole(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	const streams = 500
	arrived := make(chan string, streams)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				b, err := io.ReadAll(c)
				if err != nil {
					b = fmt.Appendf(b, ", cut by %v", err)
				}
				arrived <- string(b)
			}()
		}
	}()
	written := make(chan error, streams)
	dialers := make(chan struct{}, 8) // at a time
	want := map[string]bool{}
	for i := range streams {
		msg := fmt.Sprintf("stream %d", i)
		want[msg] = true
		dialers <- struct{}{}
		go func() {
			defer func() { <-dialers }()
			written <- writeAndClose(tr, msg)
		}()
	}
	for range streams {
		select {
		case err := <-written:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Minute):
			t.Fatal("write and close: timed out")
		}
	}
	for len(want) > 0 {
		select {
		case got := <-arrived:
			if !want[got] {
				t.Fatalf("listener read %q, want each stream written once and whole", got)
			}
			delete(want, got)
		case <-time.After(10 * time.Second):
			t.Fatalf("%d of the %d streams written and closed never arrived", len(want), streams)
		}
	}
}

func TestASlowReaderGetsAllAClosedDialerWrote(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	c, srv := connected(t, ln, tr)
	data := random(t, 2<<20)
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	closed := time.Now()
	c.Close()
	time.Sleep(time.Until(closed.Add(6 * time.Second)))
	srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	if got, err := io.ReadAll(srv); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("slow reader read %d bytes, %v; want the %d written, then EOF", len(got), err, len(data))
	}
}

func TestDialedCloseReturnsAtOnceWhenThePeerNeverReads(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	c, _ := connected(t, ln, tr)
	// Twice the peer's window, so the end of the stream queues behind data the peer never takes.
	if _, err := c.Write(make([]byte, 2<<20)); err != nil {
		t.Fatal(err)
	}
	within(t, 0, time.Second, "Close", func() { c.Close() })
}

func TestAnExpiredWriteDeadlineLosesNothingAtClose(t *testing.T) {
	ln, tr := pair(t, permuteproxy.Engine{})
	accepted := accept(t, ln)
	c := dial(t, tr)
	data := random(t, 512<<10)
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	setDeadline(t, c.SetWriteDeadline, time.Now().Add(-time.Second))
	c.Close()
	srv := recv(t, accepted, "accept")
	srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	if got, err := io.ReadAll(srv); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("listener read %d bytes, %v; want the %d written, then EOF", len(got), err, len(data))
	}
}

func TestDialedCloseReleasesOnceThePeerCloses(t *testing.T) {
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, srv := connected(t, ln, tr)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(srv); err != nil || string(got) != "x" {
		t.Fatalf("listener read %q, %v; want x, then EOF", got, err)
	}
	if n := mem.socket(t, 1).closes.Load(); n != 0 {
		t.Fatal("dialed carrier released while its peer kept the stream open")
	}
	srv.Close()
	eventuallyReleased(t, mem.socket(t, 1), 5*time.Second, "dialed")
}

func TestDialedCloseReleasesByTheLingerBound(t *testing.T) {
	quic.SetLinger(t, time.Second)
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, _ := connected(t, ln, tr)
	mem.cut()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	closed := time.Now()
	within(t, 0, time.Second, "Close", func() { c.Close() })
	eventuallyReleased(t, mem.socket(t, 1), 3*time.Second, "dialed")
	if d := time.Since(closed); d < time.Second || d >= 2*time.Second {
		t.Fatalf("dialed carrier released %v after Close, want at the linger of 1s", d)
	}
}
