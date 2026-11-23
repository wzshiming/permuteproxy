package permuteproxy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// watchedUDPEcho is testutils.UDPEcho, also signaling each datagram it receives.
func watchedUDPEcho(t *testing.T) (net.Addr, <-chan struct{}) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{}, 64)
	return testutils.ServePacketEcho(t, readSignal{pc, received}), received
}

// readSignal signals each datagram its socket reads.
type readSignal struct {
	net.PacketConn
	read chan struct{}
}

func (c readSignal) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		select {
		case c.read <- struct{}{}:
		default:
		}
	}
	return n, from, err
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

// otherPeer sends to a second echo peer through WriteTo and expects ReadFrom to name it.
func otherPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	other := testutils.UDPEcho(t)
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

var packetMessages = []string{"one", strings.Repeat("2", 1200), "three"}

func TestSOCKS5PacketEcho(t *testing.T) {
	for _, uri := range []string{"socks5://127.0.0.1:0", "socks5://u:p@127.0.0.1:0", "socks5h://127.0.0.1:0"} {
		t.Run(uri, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := parse(t, uri)
			base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
			_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
			c.Endpoint.Address = waitBound(t, base, done).String()
			clientBase := newProbe(testutils.System{})
			n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			conn := dialPacket(t, ctx, n, testutils.UDPEcho(t).String())
			for _, msg := range packetMessages {
				testutils.RoundTrip(t, conn, msg, msg)
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
			testutils.Wait(t, upstream.packetClosed, "outgoing socket close after the association closed")
		})
	}
}

func TestSOCKS5PacketRejectsBadCredentials(t *testing.T) {
	c := parse(t, "socks5://u:p@127.0.0.1:0")
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	c.Layers[0].Options = permuteproxy.Options{"username": "u", "password": "x"}
	clientBase := newProbe(testutils.System{})
	n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if conn, err := n.DialContext(ctx, "udp", testutils.UDPEcho(t).String()); err == nil {
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

// socks5TwoHops is a client through a socks5 server and on through a second one with credentials.
func socks5TwoHops(t *testing.T) (hop2 permuteproxy.Network, clientBase, firstUpstream, secondUpstream *probe) {
	t.Helper()
	first := parse(t, "socks5://127.0.0.1:0")
	firstBase, firstUpstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: firstBase, Upstream: firstUpstream}, first)
	first.Endpoint.Address = waitBound(t, firstBase, done).String()
	second := parse(t, "socks5://u:p@127.0.0.1:0")
	secondBase, secondUpstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done = start(t, permuteproxy.Engine{Base: secondBase, Upstream: secondUpstream}, second)
	second.Endpoint.Address = waitBound(t, secondBase, done).String()
	clientBase = newProbe(testutils.System{})
	hop1, err := permuteproxy.Engine{Base: clientBase}.Client(first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeIf(hop1) })
	hop2, err = permuteproxy.Engine{Base: hop1}.Client(second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeIf(hop2) })
	return hop2, clientBase, firstUpstream, secondUpstream
}

func TestSOCKS5TwoHopPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hop2, clientBase, firstUpstream, secondUpstream := socks5TwoHops(t)
	conn := dialPacket(t, ctx, hop2, testutils.UDPEcho(t).String())
	for _, msg := range packetMessages {
		testutils.RoundTrip(t, conn, msg, msg)
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
	testutils.Wait(t, secondUpstream.packetClosed, "second hop outgoing socket close")
	testutils.Wait(t, firstUpstream.packetClosed, "first hop outgoing socket close")
}

func TestNativePacketDialOverSOCKS5(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := parse(t, "socks5://127.0.0.1:0")
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBound(t, base, done).String()
	clientBase := newProbe(testutils.System{})
	proxy, err := permuteproxy.Engine{Base: clientBase}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(proxy)
	echo := testutils.UDPEcho(t)
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
		testutils.RoundTrip(t, conn, msg, msg)
	}
	otherPeer(t, conn)
	if clientBase.dials.Load() != 1 || clientBase.packets.Load() != 1 || upstream.packets.Load() != 1 {
		t.Fatalf("client base dials %d packets %d, upstream packets %d; want 1 each", clientBase.dials.Load(), clientBase.packets.Load(), upstream.packets.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	testutils.Wait(t, upstream.packetClosed, "outgoing socket close")
}

func TestSOCKS5ServerStopEndsAssociations(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := parse(t, "socks5://127.0.0.1:0")
			base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
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
			conn := dialPacket(t, ctx, n, testutils.UDPEcho(t).String())
			testutils.RoundTrip(t, conn, "before", "before")
			if stop == "close" {
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				stopRun()
			}
			waitDone(t, done)
			testutils.Wait(t, upstream.packetClosed, "outgoing socket close")
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

// okTarget serves "OK" over http for the stream side of dual-plane checks.
func okTarget(t *testing.T) string {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("OK"))
	}))
	t.Cleanup(target.Close)
	return target.URL
}

func TestShadowsocksPacketEcho(t *testing.T) {
	for _, uri := range []string{"ss://", "ss://aes-256-gcm:p@"} {
		t.Run(uri, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := parse(t, uri+testutils.ReservePort(t))
			base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
			_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
			tcp, udp := waitBound(t, base, done), waitBoundPacket(t, base, done)
			if tcp.String() != udp.String() {
				t.Fatalf("bound tcp %v and udp %v, want the declared address on both", tcp, udp)
			}
			clientBase := newProbe(testutils.System{})
			n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			conn := dialPacket(t, ctx, n, testutils.UDPEcho(t).String())
			for _, msg := range packetMessages {
				testutils.RoundTrip(t, conn, msg, msg)
			}
			otherPeer(t, conn)
			if body, err := fetch(ctx, n, okTarget(t)); err != nil || body != "OK" {
				t.Fatalf("tcp through the same server: %q, %v", body, err)
			}
			if clientBase.dials.Load() != 1 || clientBase.packets.Load() != 1 {
				t.Fatalf("client base dials %d packets %d, want 1 and 1", clientBase.dials.Load(), clientBase.packets.Load())
			}
			// The packet server keeps one outgoing socket per client and target pair.
			if upstream.dials.Load() != 1 || upstream.packets.Load() != 2 {
				t.Fatalf("upstream dials %d packets %d, want 1 and 2", upstream.dials.Load(), upstream.packets.Load())
			}
		})
	}
}

func TestShadowsocksServerStopClosesSessions(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := parse(t, "ss://"+testutils.ReservePort(t))
			base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
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
			waitBound(t, base, done)
			waitBoundPacket(t, base, done)
			n, err := permuteproxy.Engine{}.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			testutils.RoundTrip(t, dialPacket(t, ctx, n, testutils.UDPEcho(t).String()), "before", "before")
			if stop == "close" {
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				stopRun()
			}
			waitDone(t, done)
			testutils.Wait(t, base.packetClosed, "listening socket close")
			testutils.Wait(t, upstream.packetClosed, "session socket close")
			if err := srv.Close(); err != nil {
				t.Fatalf("Close after stop = %v", err)
			}
			if base.closes.Load() != 0 || upstream.closes.Load() != 0 {
				t.Fatalf("borrowed networks closed: base %d upstream %d", base.closes.Load(), upstream.closes.Load())
			}
		})
	}
}

func TestShadowsocksExplicitPlanes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Run("udp", func(t *testing.T) {
		c := parse(t, "ss+udp://127.0.0.1:0")
		base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
		_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
		c.Endpoint.Address = waitBoundPacket(t, base, done).String()
		if base.listens.Load() != 0 {
			t.Fatalf("base listens = %d for a udp-only server", base.listens.Load())
		}
		clientBase := newProbe(testutils.System{})
		n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
		if err != nil {
			t.Fatal(err)
		}
		defer closeIf(n)
		if _, err := n.DialContext(ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("DialContext(tcp) over ss+udp = %v, want ErrUnsupported", err)
		}
		testutils.RoundTrip(t, dialPacket(t, ctx, n, testutils.UDPEcho(t).String()), "udp only", "udp only")
		if clientBase.dials.Load() != 0 || clientBase.packets.Load() != 1 {
			t.Fatalf("client base dials %d packets %d, want 0 and 1", clientBase.dials.Load(), clientBase.packets.Load())
		}
	})
	t.Run("tls", func(t *testing.T) {
		c := parse(t, "ss+tls://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true")
		base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
		_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
		c.Endpoint.Address = waitBound(t, base, done).String()
		clientBase := newProbe(testutils.System{})
		n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
		if err != nil {
			t.Fatal(err)
		}
		defer closeIf(n)
		if _, err := n.DialContext(ctx, "udp", "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("DialContext(udp) over ss+tls = %v, want ErrUnsupported", err)
		}
		if _, err := n.ListenPacket(ctx, "udp", ":0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("ListenPacket over ss+tls = %v, want ErrUnsupported", err)
		}
		if body, err := fetch(ctx, n, okTarget(t)); err != nil || body != "OK" {
			t.Fatalf("tcp over ss+tls: %q, %v", body, err)
		}
		if clientBase.packets.Load() != 0 || base.packets.Load() != 0 {
			t.Fatalf("sockets opened for a stream-only carrier: client %d server %d", clientBase.packets.Load(), base.packets.Load())
		}
	})
}

type closeCountListener struct {
	net.Listener
	closes *atomic.Int32
}

func (l closeCountListener) Close() error {
	l.closes.Add(1)
	return l.Listener.Close()
}

func TestShadowsocksBindFailureReleasesListener(t *testing.T) {
	bindErr := errors.New("udp bind refused")
	var closes atomic.Int32
	base := permuteproxy.NetworkFuncs{
		ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
			ln, err := testutils.System{}.Listen(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return closeCountListener{ln, &closes}, nil
		},
		ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) { return nil, bindErr },
	}
	srv, err := permuteproxy.Engine{Base: base}.Server(parse(t, "ss://127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, bindErr) {
			t.Fatalf("Run = %v, want the udp bind error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run kept serving with only the listener bound")
	}
	if closes.Load() != 1 {
		t.Fatalf("listener closed %d times after the udp bind failed, want 1", closes.Load())
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close after the failed bind = %v", err)
	}
}

func TestShadowsocksPacketServerSurvivesGarbage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := parse(t, "ss://aes-256-gcm:p@"+testutils.ReservePort(t))
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	waitBound(t, base, done)
	udp := waitBoundPacket(t, base, done)
	garbage, err := net.Dial("udp", udp.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := garbage.Write([]byte("not shadowsocks")); err != nil {
		t.Fatal(err)
	}
	garbage.Close()
	n, err := permuteproxy.Engine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	testutils.RoundTrip(t, dialPacket(t, ctx, n, testutils.UDPEcho(t).String()), "after garbage", "after garbage")
	select {
	case err := <-done:
		t.Fatalf("server stopped after a garbage datagram: %v", err)
	default:
	}
}

func TestShadowsocksPacketServerSurvivesWrongKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := testutils.ReservePort(t)
	c := parse(t, "ss://aes-256-gcm:p@"+addr)
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	waitBound(t, base, done)
	waitBoundPacket(t, base, done)
	intruder, err := permuteproxy.Engine{}.Client(parse(t, "ss://aes-256-gcm:x@"+addr))
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(intruder)
	echo := testutils.UDPEcho(t)
	// A well-formed datagram under another key fails authentication; it must not reach the target.
	wrong := dialPacket(t, ctx, intruder, echo.String())
	if _, err := wrong.Write([]byte("wrong key")); err != nil {
		t.Fatal(err)
	}
	n, err := permuteproxy.Engine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	testutils.RoundTrip(t, dialPacket(t, ctx, n, echo.String()), "after wrong key", "after wrong key")
	if upstream.packets.Load() != 1 {
		t.Fatalf("upstream sockets = %d, want only the valid client's", upstream.packets.Load())
	}
	wrong.SetReadDeadline(time.Now())
	if n, err := wrong.Read(make([]byte, 64)); err == nil {
		t.Fatalf("the wrong-key client received %d bytes", n)
	}
	select {
	case err := <-done:
		t.Fatalf("server stopped after a wrong-key datagram: %v", err)
	default:
	}
}

func TestShadowsocksPacketServerSurvivesAnUnresolvableTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := parse(t, "ss://aes-256-gcm:p@"+testutils.ReservePort(t))
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	waitBound(t, base, done)
	waitBoundPacket(t, base, done)
	n, err := permuteproxy.Engine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	// The server looks the name up, which a NUL fails without DNS; the next datagram on the socket follows it.
	conn := dialPacket(t, ctx, n, "un\x00resolvable:9")
	if _, err := conn.Write([]byte("unresolvable")); err != nil {
		t.Fatal(err)
	}
	otherPeer(t, conn)
	if upstream.packets.Load() != 1 {
		t.Fatalf("upstream sockets = %d, want only the echo's", upstream.packets.Load())
	}
	select {
	case err := <-done:
		t.Fatalf("server stopped after a datagram to an unresolvable name: %v", err)
	default:
	}
}

// streamPayload is random bytes enough for many datagrams of a stream carried over them.
var streamPayload = func() []byte {
	b := make([]byte, 64<<10)
	rand.Read(b)
	return b
}()

// echoed writes payload to conn and wants it back whole, writing and reading aside since a cmd conn over ssh has no deadlines.
func echoed(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	got := make([]byte, len(payload))
	wrote, read := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		wrote <- err
	}()
	go func() {
		_, err := io.ReadFull(conn, got)
		read <- err
	}()
	timeout := time.After(20 * time.Second)
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-timeout:
		conn.Close()
		t.Fatalf("writing the %d bytes did not end", len(payload))
	}
	select {
	case err := <-read:
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("reading back the %d bytes written: %v, intact %v", len(payload), err, bytes.Equal(got, payload))
		}
	case <-timeout:
		conn.Close()
		t.Fatalf("the %d bytes written did not come back", len(payload))
	}
}

// tcpEcho echoes each tcp conn until the test ends, returning its address and a signal per conn it accepted.
func tcpEcho(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 64)
	return testutils.ServeEcho(t, acceptProbe{ln, accepted}).String(), accepted
}

// quicChain is the quic layer over udp at address, with a self-signed certificate.
func quicChain(address string) permuteproxy.Chain {
	return permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "quic", Options: selfSigned}}, Endpoint: permuteproxy.Endpoint{Address: address}}
}

// quicEcho echoes each stream it accepts through quic on loopback until the test ends and returns its address.
func quicEcho(t *testing.T) string {
	t.Helper()
	tr, err := permuteproxy.Engine{}.Transport(quicChain("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tr.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return testutils.ServeEcho(t, ln).String()
}

func TestQUICOverSOCKS5TwoHops(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hop2, clientBase, firstUpstream, secondUpstream := socks5TwoHops(t)
	tr, err := permuteproxy.Engine{Base: hop2}.Transport(quicChain(quicEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, streamPayload)
	// The quic socket is the second hop's association, whose own socket is the first hop's.
	if firstUpstream.dials.Load() != 1 || firstUpstream.packets.Load() != 1 {
		t.Fatalf("first upstream dials %d packets %d, want 1 and 1", firstUpstream.dials.Load(), firstUpstream.packets.Load())
	}
	if secondUpstream.dials.Load() != 0 || secondUpstream.packets.Load() != 1 {
		t.Fatalf("second upstream dials %d packets %d, want 0 and 1", secondUpstream.dials.Load(), secondUpstream.packets.Load())
	}
	if clientBase.dials.Load() != 2 || clientBase.packets.Load() != 1 {
		t.Fatalf("client base dials %d packets %d, want two control conns and one socket", clientBase.dials.Load(), clientBase.packets.Load())
	}
}

func TestQUICOverShadowsocksPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := parse(t, "ss+udp://aes-256-gcm:p@127.0.0.1:0")
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBoundPacket(t, base, done).String()
	clientBase := newProbe(testutils.System{})
	ss, err := permuteproxy.Engine{Base: clientBase}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(ss)
	tr, err := permuteproxy.Engine{Base: ss}.Transport(quicChain(quicEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, streamPayload)
	// The client seals the quic datagrams on one socket, which the server relays from one of its own, closing at once any other it opened for the first flight.
	if clientBase.dials.Load() != 0 || clientBase.packets.Load() != 1 {
		t.Fatalf("client base dials %d packets %d, want 0 and 1", clientBase.dials.Load(), clientBase.packets.Load())
	}
	if open := upstream.packets.Load() - int32(len(upstream.packetClosed)); upstream.dials.Load() != 0 || open != 1 {
		t.Fatalf("upstream dials %d, sockets left open %d of %d opened, want 0 and 1", upstream.dials.Load(), open, upstream.packets.Load())
	}
}

func TestShadowsocksStreamOverQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := parse(t, "ss+quic://aes-256-gcm:p@127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true")
	base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
	_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
	c.Endpoint.Address = waitBoundPacket(t, base, done).String()
	clientBase := newProbe(testutils.System{})
	n, err := permuteproxy.Engine{Base: clientBase}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIf(n)
	echo, _ := tcpEcho(t)
	conn, err := n.DialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoed(t, conn, streamPayload)
	// quic offers ss a stream only, so the client has no datagrams to give.
	if _, err := n.DialContext(ctx, "udp", testutils.UDPEcho(t).String()); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(udp) over ss+quic = %v, want ErrUnsupported", err)
	}
	if clientBase.dials.Load() != 0 || clientBase.packets.Load() != 1 {
		t.Fatalf("client base dials %d packets %d, want 0 and 1", clientBase.dials.Load(), clientBase.packets.Load())
	}
	if base.listens.Load() != 0 || base.packets.Load() != 1 {
		t.Fatalf("server base listens %d packets %d, want 0 and 1", base.listens.Load(), base.packets.Load())
	}
	if upstream.dials.Load() != 1 || upstream.packets.Load() != 0 {
		t.Fatalf("upstream dials %d packets %d, want 1 and 0", upstream.dials.Load(), upstream.packets.Load())
	}
}

func TestSSAndQUICRefuseNetcatUDP(t *testing.T) {
	// Valid alone, so the refusals below are of the compositions and not of an unknown network.
	if _, err := permuteproxy.ParseURI("cmd-nc-udp://127.0.0.1:53"); err != nil {
		t.Fatalf("cmd-nc-udp alone = %v, want it valid", err)
	}
	for _, layer := range []string{"ss", "quic"} {
		if _, err := permuteproxy.ParseURI(layer + "+udp://127.0.0.1:53"); err != nil {
			t.Errorf("%s over udp = %v, want it valid", layer, err)
		}
		// nc carries the datagrams in a stream, which keeps no boundaries between them.
		if _, err := permuteproxy.ParseURI(layer + "+cmd-nc-udp://127.0.0.1:53"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("%s over cmd-nc-udp = %v, want ErrInvalidChain", layer, err)
		}
	}
}
