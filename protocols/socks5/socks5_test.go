package socks5

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
)

var system permuteproxy.Network = permuteproxy.NetworkFuncs{
	DialContextFunc:  (&net.Dialer{}).DialContext,
	ListenFunc:       (&net.ListenConfig{}).Listen,
	ListenPacketFunc: (&net.ListenConfig{}).ListenPacket,
}

// closeProbe counts what a client or server takes from a network and how often each is closed;
// packetClosed signals every socket close for closes the libraries perform asynchronously.
type closeProbe struct {
	permuteproxy.Network
	dials, packets             atomic.Int32
	closedConns, closedPackets atomic.Int32
	packetClosed               chan struct{}
}

func newProbe(n permuteproxy.Network) *closeProbe {
	return &closeProbe{Network: n, packetClosed: make(chan struct{}, 64)}
}

type countingConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c countingConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

type countingPacket struct {
	net.PacketConn
	closed *atomic.Int32
	signal chan struct{}
}

func (c countingPacket) Close() error {
	c.closed.Add(1)
	select {
	case c.signal <- struct{}{}:
	default:
	}
	return c.PacketConn.Close()
}

func (p *closeProbe) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	p.dials.Add(1)
	conn, err := p.Network.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return countingConn{conn, &p.closedConns}, nil
}

func (p *closeProbe) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	p.packets.Add(1)
	pc, err := p.Network.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return countingPacket{pc, &p.closedPackets, p.packetClosed}, nil
}

// serve runs a socks5 server on a loopback tcp listener and returns its address.
func serve(t *testing.T, upstream permuteproxy.Network, opts permuteproxy.Options) string {
	t.Helper()
	bound := make(chan net.Addr, 1)
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, ListenFunc: func(ctx context.Context) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}}
	srv, err := NewServer(inner, upstream, opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after Close")
		}
	})
	select {
	case addr := <-bound:
		return addr.String()
	case err := <-done:
		t.Fatalf("server exited before binding: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not bind")
	}
	return ""
}

// dialer builds a socks5 client whose control conns and sockets both come from base; resolve
// picks socks5 (names resolved locally) over socks5h.
func dialer(t *testing.T, base permuteproxy.Network, address string, opts permuteproxy.Options, resolve bool) permuteproxy.Network {
	t.Helper()
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(ctx context.Context, _ permuteproxy.Plane) (net.Conn, error) {
		return base.DialContext(ctx, "tcp", address)
	}}
	n, err := newClient(inner, base, opts, resolve)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func echo(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	return pc
}

func TestAssociationCloseEndsControlAndSocket(t *testing.T) {
	upstream := newProbe(system)
	addr := serve(t, upstream, nil)
	base := newProbe(system)
	n := dialer(t, base, addr, nil, true)
	peer := echo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := n.DialContext(ctx, "udp", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	if base.dials.Load() != 1 || base.packets.Load() != 1 {
		t.Fatalf("base dials %d packets %d, want 1 and 1", base.dials.Load(), base.packets.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if base.closedConns.Load() != 1 || base.closedPackets.Load() != 1 {
		t.Fatalf("closed conns %d packets %d after Close, want 1 and 1", base.closedConns.Load(), base.closedPackets.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if base.closedConns.Load() != 1 || base.closedPackets.Load() != 1 {
		t.Fatal("second Close reached the base conns again")
	}
}

func TestAssociationFailuresCloseControl(t *testing.T) {
	bindErr := errors.New("no socket")
	tests := []struct {
		name     string
		server   permuteproxy.Options
		client   permuteproxy.Options
		noSocket bool
	}{
		{"wrong password", permuteproxy.Options{KeyUsername: "u", KeyPassword: "p"}, permuteproxy.Options{KeyUsername: "u", KeyPassword: "x"}, false},
		{"missing credentials", permuteproxy.Options{KeyUsername: "u", KeyPassword: "p"}, nil, false},
		{"socket bind fails", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := newProbe(system)
			addr := serve(t, upstream, tt.server)
			base := newProbe(system)
			if tt.noSocket {
				base.Network = permuteproxy.NetworkFuncs{
					DialContextFunc:  system.DialContext,
					ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) { return nil, bindErr },
				}
			}
			n := dialer(t, base, addr, tt.client, true)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := n.DialContext(ctx, "udp", "127.0.0.1:9")
			if err == nil {
				conn.Close()
				t.Fatal("DialContext succeeded")
			}
			if tt.noSocket && !errors.Is(err, bindErr) {
				t.Fatalf("DialContext = %v, want the bind error", err)
			}
			if base.dials.Load() != 1 || base.closedConns.Load() != 1 {
				t.Fatalf("control conns: %d dialed, %d closed; want 1 and 1", base.dials.Load(), base.closedConns.Load())
			}
			if !tt.noSocket && base.packets.Load() != 0 {
				t.Fatalf("socket opened %d times before the handshake failed", base.packets.Load())
			}
			if tt.noSocket {
				// The proxy had already granted the association; closing the control conn must end it.
				select {
				case <-upstream.packetClosed:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream socket survived the failed association")
				}
			} else if upstream.packets.Load() != 0 {
				t.Fatalf("upstream ListenPacket called %d times for a refused client", upstream.packets.Load())
			}
		})
	}
}

func TestAssociationCanceledHandshakeClosesControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	base := newProbe(system)
	n := dialer(t, base, ln.Addr().String(), nil, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn := <-accepted
		defer conn.Close()
		// The server stays silent; cancel once the greeting has arrived.
		conn.Read(make([]byte, 1))
		cancel()
	}()
	done := make(chan error, 1)
	go func() {
		conn, err := n.DialContext(ctx, "udp", "127.0.0.1:9")
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialContext kept waiting on a silent proxy after cancellation")
	}
	if base.closedConns.Load() != 1 || base.packets.Load() != 0 {
		t.Fatalf("closed conns %d, sockets %d; want 1 and 0", base.closedConns.Load(), base.packets.Load())
	}
}

func TestAssociationSurvivesLaterCancel(t *testing.T) {
	addr := serve(t, newProbe(system), nil)
	base := newProbe(system)
	n := dialer(t, base, addr, nil, true)
	peer := echo(t)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := n.DialContext(ctx, "udp", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("Read after the dial context was canceled = %q, %v", buf[:n], err)
	}
	if base.closedConns.Load() != 0 {
		t.Fatal("canceling the dial context closed an established association")
	}
}

func TestServerStopEndsAssociation(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			upstream := newProbe(system)
			bound := make(chan net.Addr, 1)
			inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, ListenFunc: func(ctx context.Context) (net.Listener, error) {
				ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
				if err == nil {
					bound <- ln.Addr()
				}
				return ln, err
			}}
			srv, err := NewServer(inner, upstream, nil)
			if err != nil {
				t.Fatal(err)
			}
			runCtx, stopRun := context.WithCancel(context.Background())
			defer stopRun()
			done := make(chan error, 1)
			go func() { done <- srv.Run(runCtx) }()
			defer srv.Close()
			var addr net.Addr
			select {
			case addr = <-bound:
			case <-time.After(5 * time.Second):
				t.Fatal("server did not bind")
			}
			base := newProbe(system)
			n := dialer(t, base, addr.String(), nil, true)
			peer := echo(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := n.DialContext(ctx, "udp", peer.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ping" {
				t.Fatalf("Read = %q, %v", buf[:n], err)
			}
			if upstream.packets.Load() != 1 {
				t.Fatalf("upstream sockets = %d, want 1", upstream.packets.Load())
			}
			if stop == "close" {
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				stopRun()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return")
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Read(buf); err == nil || isTimeout(err) {
				t.Fatalf("client Read after the server stopped = %v, want the closed association", err)
			}
			select {
			case <-upstream.packetClosed:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream socket survived the server stop")
			}
		})
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// stubResolver routes DNS through dial so tests see whether a name was resolved locally.
func stubResolver(t *testing.T, dial func(ctx context.Context, network, address string) (net.Conn, error)) {
	t.Helper()
	prev := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: dial}
	t.Cleanup(func() { net.DefaultResolver = prev })
}

func TestAssociationNameResolution(t *testing.T) {
	var lookups atomic.Int32
	stubResolver(t, func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("no dns")
	})
	addr := serve(t, newProbe(system), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := newProbe(system)
	if conn, err := dialer(t, base, addr, nil, true).DialContext(ctx, "udp", "proxy.invalid:9"); err == nil {
		conn.Close()
		t.Fatal("socks5 dialed a name that does not resolve")
	}
	if lookups.Load() == 0 || base.dials.Load() != 0 {
		t.Fatalf("socks5: %d lookups, %d control conns; want a local lookup before any conn", lookups.Load(), base.dials.Load())
	}
	lookups.Store(0)
	base = newProbe(system)
	conn, err := dialer(t, base, addr, nil, false).DialContext(ctx, "udp", "proxy.invalid:9")
	if err != nil {
		t.Fatalf("socks5h: %v", err)
	}
	defer conn.Close()
	if lookups.Load() != 0 {
		t.Fatalf("socks5h resolved the name locally %d times", lookups.Load())
	}
	if got := conn.RemoteAddr().String(); got != "proxy.invalid:9" {
		t.Fatalf("socks5h RemoteAddr() = %q, want the name kept for the proxy", got)
	}
}

type addrOnly struct {
	net.Conn
	local net.Addr
}

func (a addrOnly) LocalAddr() net.Addr { return a.local }

type packetAddrOnly struct {
	net.PacketConn
	local net.Addr
}

func (a packetAddrOnly) LocalAddr() net.Addr { return a.local }

func TestRelayAddress(t *testing.T) {
	tests := []struct {
		name    string
		relay   net.Addr
		control net.Addr
		want    string
	}{
		{"tcp v4 control", &net.UDPAddr{IP: net.IPv6unspecified, Port: 7}, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}, "10.0.0.1:7"},
		{"tcp v6 control", &net.UDPAddr{IP: net.IPv6unspecified, Port: 7}, &net.TCPAddr{IP: net.IPv6loopback, Port: 1080}, "[::1]:7"},
		{"unix control v4 relay", &net.UDPAddr{IP: net.IPv4zero, Port: 7}, &net.UnixAddr{Name: "/tmp/s", Net: "unix"}, "127.0.0.1:7"},
		{"unix control v6 relay", &net.UDPAddr{IP: net.IPv6unspecified, Port: 7}, &net.UnixAddr{Name: "/tmp/s", Net: "unix"}, "[::1]:7"},
		{"unix control specific relay", &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 7}, &net.UnixAddr{Name: "/tmp/s", Net: "unix"}, "10.0.0.2:7"},
		{"relay not udp", &net.UnixAddr{Name: "/tmp/p", Net: "unixgram"}, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := relayAddress(context.Background(), "", packetAddrOnly{local: tt.relay}, addrOnly{local: tt.control})
			if tt.want == "" {
				if err == nil {
					t.Fatalf("relayAddress = %v:%d, want an error", ip, port)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := (&net.UDPAddr{IP: ip, Port: port}).String(); got != tt.want {
				t.Fatalf("relayAddress = %q, want %q", got, tt.want)
			}
		})
	}
}
