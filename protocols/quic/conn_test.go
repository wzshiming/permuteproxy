package quic_test

import (
	"errors"
	"io"
	"net"
	"os"
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
