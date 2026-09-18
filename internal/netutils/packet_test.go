package netutils

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

var systemListen = (&net.ListenConfig{}).ListenPacket

var packetNetworks = []string{"udp", "udp4", "udp6", "unixgram"}

// peerAddress is a free address for a peer on the network; unixgram paths stay short for sun_path.
func peerAddress(t *testing.T, network string) string {
	t.Helper()
	switch network {
	case "udp6":
		return "[::1]:0"
	case "unixgram":
		if runtime.GOOS == "windows" {
			t.Skip("unixgram needs a POSIX system")
		}
		return filepath.Join(t.TempDir(), "p")
	}
	return "127.0.0.1:0"
}

// echo answers every datagram to its sender until the test ends.
func echo(t *testing.T, network string) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket(network, peerAddress(t, network))
	if err != nil {
		t.Skipf("%s unavailable: %v", network, err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr()
}

func datagram(size int) []byte {
	return bytes.Repeat([]byte{byte(size)}, size)
}

// sameSource reports whether seen, the source a peer observed, is the wildcard-bound local.
func sameSource(seen, local net.Addr) bool {
	if s, ok := seen.(*net.UDPAddr); ok {
		l := local.(*net.UDPAddr)
		return s.Port == l.Port && (l.IP.IsUnspecified() || l.IP.Equal(s.IP))
	}
	return seen.String() == local.String()
}

func TestDialPacketEcho(t *testing.T) {
	for _, network := range packetNetworks {
		t.Run(network, func(t *testing.T) {
			peer := echo(t, network)
			conn, err := DialPacket(context.Background(), network, peer.String(), systemListen)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, ok := conn.(net.PacketConn); !ok {
				t.Fatal("conn is not a net.PacketConn")
			}
			if got := conn.RemoteAddr().String(); got != peer.String() {
				t.Fatalf("RemoteAddr() = %q, want %q", got, peer.String())
			}
			buf := make([]byte, 2048)
			for _, sizes := range [][]int{{1, 700}, {3, 1000}} {
				for _, size := range sizes {
					if _, err := conn.Write(datagram(size)); err != nil {
						t.Fatal(err)
					}
				}
				for _, size := range sizes {
					n, err := conn.Read(buf)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(buf[:n], datagram(size)) {
						t.Fatalf("Read = %d bytes, want the %d-byte datagram", n, size)
					}
				}
			}
		})
	}
}

func TestDialPacketOtherPeer(t *testing.T) {
	for _, network := range packetNetworks {
		t.Run(network, func(t *testing.T) {
			peer := echo(t, network)
			other, err := net.ListenPacket(network, peerAddress(t, network))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			conn, err := DialPacket(context.Background(), network, peer.String(), systemListen)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			pc := conn.(net.PacketConn)
			if _, err := pc.WriteTo([]byte("other"), other.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, from, err := other.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf[:n]) != "other" || !sameSource(from, conn.LocalAddr()) {
				t.Fatalf("other peer got %q from %v, want \"other\" from %v", buf[:n], from, conn.LocalAddr())
			}
			if _, err := other.WriteTo([]byte("back"), from); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("echoed")); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"back": other.LocalAddr().String(), "echoed": peer.String()}
			for range want {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if got := want[string(buf[:n])]; got != from.String() {
					t.Fatalf("ReadFrom = %q from %v, want it from %q", buf[:n], from, got)
				}
				delete(want, string(buf[:n]))
			}
		})
	}
}

func TestDialPacketFamilies(t *testing.T) {
	for network, v4 := range map[string]bool{"udp4": true, "udp6": false} {
		peer := echo(t, network)
		conn, err := DialPacket(context.Background(), network, peer.String(), systemListen)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		local := conn.LocalAddr().(*net.UDPAddr)
		if (local.IP.To4() != nil) != v4 {
			t.Fatalf("%s LocalAddr() = %v", network, local)
		}
		if _, ok := conn.RemoteAddr().(*net.UDPAddr); !ok {
			t.Fatalf("%s RemoteAddr() = %T, want *net.UDPAddr", network, conn.RemoteAddr())
		}
	}
	for network, address := range map[string]string{"udp4": "[::1]:1", "udp6": "127.0.0.1:1"} {
		if conn, err := DialPacket(context.Background(), network, address, systemListen); err == nil {
			conn.Close()
			t.Fatalf("DialPacket(%s, %s) succeeded", network, address)
		}
	}
}

func TestDialPacketLifecycle(t *testing.T) {
	for _, network := range packetNetworks {
		t.Run(network, func(t *testing.T) {
			peer := echo(t, network)
			conn, err := DialPacket(context.Background(), network, peer.String(), systemListen)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			if _, err := conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read after deadline = %v, want a deadline error", err)
			}
			if err := conn.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			read := make(chan error, 1)
			go func() { _, err := conn.Read(buf); read <- err }()
			time.Sleep(20 * time.Millisecond)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-read:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Read after Close = %v, want net.ErrClosed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not unblock Read")
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("second Close = %v", err)
			}
			if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
			}
		})
	}
}

// countingListen counts listen calls and the Close calls on what it returned.
type countingListen struct {
	listens, closes atomic.Int32
	before          func()
}

func (l *countingListen) listen(ctx context.Context, network, address string) (net.PacketConn, error) {
	l.listens.Add(1)
	if l.before != nil {
		l.before()
	}
	pc, err := systemListen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return closeCounter{pc, &l.closes}, nil
}

type closeCounter struct {
	net.PacketConn
	closes *atomic.Int32
}

func (c closeCounter) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

func TestDialPacketRefuses(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		network string
		address string
		want    error
	}{
		{"canceled", canceled, "udp", "127.0.0.1:1", context.Canceled},
		{"invalid udp", context.Background(), "udp", "127.0.0.1", nil},
		{"port out of range", context.Background(), "udp", "127.0.0.1:65536", nil},
		{"empty udp", context.Background(), "udp", "", nil},
		{"empty unixgram", context.Background(), "unixgram", "", nil},
		{"stream", context.Background(), "tcp", "127.0.0.1:1", nil},
		{"unknown", context.Background(), "bogus", "x", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &countingListen{}
			conn, err := DialPacket(tt.ctx, tt.network, tt.address, l.listen)
			if err == nil {
				conn.Close()
				t.Fatal("DialPacket succeeded")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("DialPacket = %v, want %v", err, tt.want)
			}
			if got := l.listens.Load(); got != 0 {
				t.Fatalf("listen called %d times", got)
			}
		})
	}
}

func TestDialPacketCancelDuringListen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &countingListen{before: cancel}
	conn, err := DialPacket(ctx, "udp", "127.0.0.1:1", l.listen)
	if err == nil {
		conn.Close()
		t.Fatal("DialPacket succeeded after its context was canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialPacket = %v, want context.Canceled", err)
	}
	if l.listens.Load() != 1 || l.closes.Load() != 1 {
		t.Fatalf("listens = %d, closes = %d, want the one socket closed", l.listens.Load(), l.closes.Load())
	}
}

// stubResolver routes DNS through dial until the test ends; PreferGo keeps libc from bypassing it.
func stubResolver(t *testing.T, dial func(ctx context.Context, network, address string) (net.Conn, error)) {
	t.Helper()
	prev := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: dial}
	t.Cleanup(func() { net.DefaultResolver = prev })
}

func TestDialPacketCancelDuringResolve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	over := make(chan struct{})
	stubResolver(t, func(dns context.Context, _, _ string) (net.Conn, error) {
		cancel()
		select {
		case <-dns.Done():
		case <-over:
		}
		return nil, errors.New("blocked")
	})
	l := &countingListen{}
	errc := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := DialPacket(ctx, "udp", "resolve.invalid:1", l.listen)
		if err == nil {
			conn.Close()
		}
		errc <- err
	}()
	t.Cleanup(func() { close(over); <-done })
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialPacket = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialPacket kept waiting for DNS after its context was canceled")
	}
	if got := l.listens.Load(); got != 0 {
		t.Fatalf("listen called %d times", got)
	}
}

func TestDialPacketLiterals(t *testing.T) {
	var dialed atomic.Int32
	stubResolver(t, func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("literals must not reach DNS")
	})
	for _, address := range []string{"127.0.0.1:1", "[::1]:2", "[fe80::1%lo0]:3", ":4"} {
		conn, err := DialPacket(context.Background(), "udp", address, systemListen)
		if err != nil {
			t.Fatalf("DialPacket(%q) = %v", address, err)
		}
		got := conn.RemoteAddr().String()
		conn.Close()
		if got != address {
			t.Fatalf("DialPacket(%q).RemoteAddr() = %q", address, got)
		}
	}
	if n := dialed.Load(); n != 0 {
		t.Fatalf("literals reached DNS %d times", n)
	}
}

func TestDialPacketUnixgramPath(t *testing.T) {
	peer := echo(t, "unixgram")
	var offered string
	conn, err := DialPacket(context.Background(), "unixgram", peer.String(), func(_ context.Context, _, address string) (net.PacketConn, error) {
		offered = address
		return nil, errors.New("refused")
	})
	if err == nil {
		conn.Close()
		t.Fatal("DialPacket succeeded through a failing listen")
	}
	if offered == "" || offered == ":0" {
		t.Fatalf("listen offered %q, want a private socket path", offered)
	}
	if _, err := os.Stat(filepath.Dir(offered)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed listen left %q behind: %v", filepath.Dir(offered), err)
	}
	conn, err = DialPacket(context.Background(), "unixgram", peer.String(), systemListen)
	if err != nil {
		t.Fatal(err)
	}
	local := conn.LocalAddr().String()
	if filepath.Dir(local) == filepath.Dir(peer.String()) {
		t.Fatalf("LocalAddr() = %q, want a private socket path", local)
	}
	if fi, err := os.Lstat(local); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("local socket %q: %v %v", local, fi, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(local)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private directory of %q survived Close: %v", local, err)
	}
	if _, err := os.Stat(peer.String()); err != nil {
		t.Fatalf("peer socket removed: %v", err)
	}
}
