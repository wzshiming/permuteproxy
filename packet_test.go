package permuteproxy_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
)

// udpEcho answers every datagram to its sender until the test ends.
func udpEcho(t *testing.T) net.Addr {
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
	return pc.LocalAddr()
}

// dialPacket dials target over udp through n; the conn must also be a net.PacketConn.
func dialPacket(t *testing.T, ctx context.Context, n permuteproxy.Network, target string) net.Conn {
	t.Helper()
	conn, err := n.DialContext(ctx, "udp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatal("udp conn is not a net.PacketConn")
	}
	if conn.RemoteAddr().String() != target {
		t.Fatalf("RemoteAddr() = %v, want %s", conn.RemoteAddr(), target)
	}
	return conn
}

// roundTrip sends msg to the conn's peer and expects it echoed back as one datagram.
func roundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("Read = %d bytes, %v; want the %d-byte datagram back", n, err, len(msg))
	}
}

// otherPeer sends to a second echo peer through WriteTo and expects ReadFrom to name it.
func otherPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	other := udpEcho(t)
	pc := conn.(net.PacketConn)
	if _, err := pc.WriteTo([]byte("other"), other); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "other" || from.String() != other.String() {
		t.Fatalf("ReadFrom = %q from %v, %v; want \"other\" from %v", buf[:n], from, err, other)
	}
}

func signaled(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen", what)
	}
}

var packetMessages = []string{"one", strings.Repeat("2", 1200), "three"}

func TestSOCKS5PacketEcho(t *testing.T) {
	for _, uri := range []string{"socks5://127.0.0.1:0", "socks5://u:p@127.0.0.1:0", "socks5h://127.0.0.1:0"} {
		t.Run(uri, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := parse(t, uri)
			base, upstream := newProbe(system), newProbe(system)
			_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
			c.Endpoint.Address = waitBound(t, base, done).String()
			clientBase := newProbe(system)
			n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			conn := dialPacket(t, ctx, n, udpEcho(t).String())
			for _, msg := range packetMessages {
				roundTrip(t, conn, msg)
			}
			otherPeer(t, conn)
			if clientBase.dials.Load() != 1 || clientBase.packets.Load() != 1 {
				t.Fatalf("client base dials %d packets %d, want one control conn and one socket", clientBase.dials.Load(), clientBase.packets.Load())
			}
			if upstream.packets.Load() != 1 || upstream.dials.Load() != 0 {
				t.Fatalf("upstream packets %d dials %d, want one outgoing socket and no dial", upstream.packets.Load(), upstream.dials.Load())
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			signaled(t, upstream.packetClosed, "outgoing socket close after the association closed")
		})
	}
}

func TestSOCKS5PacketRejectsBadCredentials(t *testing.T) {
	c := parse(t, "socks5://u:p@127.0.0.1:0")
	base, upstream := newProbe(system), newProbe(system)
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	c.Layers[0].Options = permuteproxy.Options{"username": "u", "password": "x"}
	clientBase := newProbe(system)
	n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if conn, err := n.DialContext(ctx, "udp", udpEcho(t).String()); err == nil {
		conn.Close()
		t.Fatal("association with bad credentials succeeded")
	}
	if clientBase.dials.Load() != 1 || clientBase.packets.Load() != 0 {
		t.Fatalf("client base dials %d packets %d, want 1 and 0", clientBase.dials.Load(), clientBase.packets.Load())
	}
	if upstream.packets.Load() != 0 {
		t.Fatalf("upstream opened %d sockets for a refused client", upstream.packets.Load())
	}
}

func TestSOCKS5TwoHopPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first := parse(t, "socks5://127.0.0.1:0")
	firstBase, firstUpstream := newProbe(system), newProbe(system)
	_, done := start(t, permuteproxy.Engine{Base: firstBase, Upstream: firstUpstream}, first)
	first.Endpoint.Address = waitBound(t, firstBase, done).String()
	second := parse(t, "socks5://u:p@127.0.0.1:0")
	secondBase, secondUpstream := newProbe(system), newProbe(system)
	_, done = start(t, permuteproxy.Engine{Base: secondBase, Upstream: secondUpstream}, second)
	second.Endpoint.Address = waitBound(t, secondBase, done).String()
	clientBase := newProbe(system)
	hop1, err := permuteproxy.Engine{Base: clientBase}.Client(first)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(hop1)
	hop2, err := permuteproxy.Engine{Base: hop1}.Client(second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(hop2)
	conn := dialPacket(t, ctx, hop2, udpEcho(t).String())
	for _, msg := range packetMessages {
		roundTrip(t, conn, msg)
	}
	otherPeer(t, conn)
	// The first hop carried the second hop's control conn and its socket; only the second hop egresses.
	if firstUpstream.dials.Load() != 1 || firstUpstream.packets.Load() != 1 {
		t.Fatalf("first upstream dials %d packets %d, want 1 and 1", firstUpstream.dials.Load(), firstUpstream.packets.Load())
	}
	if secondUpstream.dials.Load() != 0 || secondUpstream.packets.Load() != 1 {
		t.Fatalf("second upstream dials %d packets %d, want 0 and 1", secondUpstream.dials.Load(), secondUpstream.packets.Load())
	}
	if clientBase.dials.Load() != 2 || clientBase.packets.Load() != 1 {
		t.Fatalf("client base dials %d packets %d, want two control conns and one socket", clientBase.dials.Load(), clientBase.packets.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	signaled(t, secondUpstream.packetClosed, "second hop outgoing socket close")
	signaled(t, firstUpstream.packetClosed, "first hop outgoing socket close")
}

func TestNativePacketDialOverSOCKS5(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := parse(t, "socks5://127.0.0.1:0")
	base, upstream := newProbe(system), newProbe(system)
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	clientBase := newProbe(system)
	proxy, err := permuteproxy.Engine{Base: clientBase}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(proxy)
	echo := udpEcho(t)
	tr, err := permuteproxy.Engine{Base: proxy}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "udp", Address: echo.String()}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != echo.String() {
		t.Fatalf("RemoteAddr() = %v, want %v", conn.RemoteAddr(), echo)
	}
	for _, msg := range packetMessages {
		roundTrip(t, conn, msg)
	}
	otherPeer(t, conn)
	if clientBase.dials.Load() != 1 || clientBase.packets.Load() != 1 || upstream.packets.Load() != 1 {
		t.Fatalf("client base dials %d packets %d, upstream packets %d; want 1 each", clientBase.dials.Load(), clientBase.packets.Load(), upstream.packets.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	signaled(t, upstream.packetClosed, "outgoing socket close")
}

func TestSOCKS5ServerStopEndsAssociations(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := parse(t, "socks5://127.0.0.1:0")
			base, upstream := newProbe(system), newProbe(system)
			srv, err := permuteproxy.Engine{Base: base, Upstream: upstream}.Server(c)
			if err != nil {
				t.Fatal(err)
			}
			runCtx, stopRun := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- srv.Run(runCtx) }()
			t.Cleanup(func() {
				srv.Close()
				stopRun()
			})
			c.Endpoint.Address = waitBound(t, base, done).String()
			n, err := permuteproxy.Engine{}.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			conn := dialPacket(t, ctx, n, udpEcho(t).String())
			roundTrip(t, conn, "before")
			if stop == "close" {
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				stopRun()
			}
			waitDone(t, done)
			signaled(t, upstream.packetClosed, "outgoing socket close")
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var ne net.Error
			if _, err := conn.Read(make([]byte, 16)); err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Fatalf("client Read after the server stopped = %v, want the closed association", err)
			}
			if base.closes.Load() != 0 || upstream.closes.Load() != 0 {
				t.Fatalf("borrowed networks closed: base %d upstream %d", base.closes.Load(), upstream.closes.Load())
			}
		})
	}
}
