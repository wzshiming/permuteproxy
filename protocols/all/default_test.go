package all_test

import (
	"errors"
	"io"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// TestDefaultNetwork reaches each kind of registered network by its name alone.
func TestDefaultNetwork(t *testing.T) {
	ctx, n := t.Context(), permuteproxy.DefaultNetwork

	t.Run("implemented", func(t *testing.T) {
		ln, err := n.Listen(ctx, "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := n.DialContext(ctx, "tcp4", testutils.ServeEcho(t, ln).String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		echoedStream(t, conn)
	})

	t.Run("command", func(t *testing.T) {
		conn, err := n.DialContext(ctx, "cmd", "cat")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		echoedStream(t, conn)
	})

	t.Run("expression", func(t *testing.T) {
		conn, err := n.DialContext(ctx, "cmd-packet", "cat")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, ok := conn.(net.PacketConn); !ok {
			t.Errorf("a datagram network dialed %T, not a net.PacketConn", conn)
		}
		testutils.RoundTrip(t, conn, "ping", "ping")
		if _, err := n.ListenPacket(ctx, "cmd-packet", "cat"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Errorf("ListenPacket on a network with neither a Listen expression nor an implementation = %v, want %v", err, permuteproxy.ErrUnsupported)
		}
	})

	t.Run("listen expression", func(t *testing.T) {
		if _, err := exec.LookPath("nc"); err != nil {
			t.Skipf("nc unavailable: %v", err)
		}
		address := testutils.ReservePort(t)
		ln, err := n.Listen(ctx, "cmd-nc", address)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			io.Copy(conn, conn)
		}()
		conn := dialRetry(t, n, address)
		defer conn.Close()
		echoedStream(t, conn)
	})

	t.Run("lossy", func(t *testing.T) {
		l := n.(permuteproxy.LossyNetwork)
		for network, want := range map[string]bool{"udp": false, "tcp": false, "cmd-packet": true, "cmd-nc-udp": true, "unknown": false} {
			if got := l.Lossy(network); got != want {
				t.Errorf("Lossy(%q) = %v, want %v", network, got, want)
			}
		}
	})

	t.Run("unknown", func(t *testing.T) {
		for _, network := range []string{"unknown", "nc", "socks5"} {
			if _, err := n.DialContext(ctx, network, "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
				t.Errorf("dial %s = %v, want %v", network, err, permuteproxy.ErrUnsupported)
			}
			if _, err := n.Listen(ctx, network, "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
				t.Errorf("listen %s = %v, want %v", network, err, permuteproxy.ErrUnsupported)
			}
			if _, err := n.ListenPacket(ctx, network, "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
				t.Errorf("listen packet %s = %v, want %v", network, err, permuteproxy.ErrUnsupported)
			}
		}
	})
}

// echoedStream writes ping to a stream conn and wants it back, in however many reads.
func echoedStream(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q, %v; want the echo", buf, err)
	}
}
