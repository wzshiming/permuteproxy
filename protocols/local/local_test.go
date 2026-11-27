package local

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestLocalRefusesNetworksItDoesNotHandle(t *testing.T) {
	ctx := context.Background()
	for op, call := range map[string]func() error{
		"dial cmd-nc":              func() error { _, err := Network.DialContext(ctx, "cmd-nc", "127.0.0.1:1"); return err },
		"listen cmd-nc":            func() error { _, err := Network.Listen(ctx, "cmd-nc", "127.0.0.1:1"); return err },
		"listen packet cmd-nc-udp": func() error { _, err := Network.ListenPacket(ctx, "cmd-nc-udp", "127.0.0.1:1"); return err },
	} {
		var unknown net.UnknownNetworkError
		if err := call(); !errors.Is(err, permuteproxy.ErrUnsupported) || !errors.As(err, &unknown) {
			t.Errorf("%s = %v, want ErrUnsupported keeping the system's unknown network error", op, err)
		}
	}
}

func TestDialPacket(t *testing.T) {
	ctx := context.Background()
	for network, address := range map[string]string{"udp": "127.0.0.1:0", "unixgram": filepath.Join(t.TempDir(), "p")} {
		t.Run(network, func(t *testing.T) {
			if network == "unixgram" && runtime.GOOS == "windows" {
				t.Skip("unixgram needs a POSIX system")
			}
			peer, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			conn, err := Network.DialContext(ctx, network, peer.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			pc, ok := conn.(net.PacketConn)
			if !ok {
				t.Fatal("conn is not a net.PacketConn")
			}
			// A connected socket refuses WriteTo; the peer must also see a source it can answer.
			if _, err := pc.WriteTo([]byte("ping"), peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			n, from, err := peer.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "ping" {
				t.Fatalf("peer read %q, %v", buf[:n], err)
			}
			if _, err := peer.WriteTo([]byte("pong"), from); err != nil {
				t.Fatal(err)
			}
			if n, err = conn.Read(buf); err != nil || string(buf[:n]) != "pong" {
				t.Fatalf("Read = %q, %v", buf[:n], err)
			}
			if network != "unixgram" {
				return
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Dir(from.String())); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("private directory of %v survived Close: %v", from, err)
			}
		})
	}
}

func TestDialFamilies(t *testing.T) {
	ctx := context.Background()
	udp, err := Network.DialContext(ctx, "udp4", testutils.UDPEcho(t).String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	echoes(t, udp, "ping")
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcp, err := Network.DialContext(ctx, "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcp.Close()
}
