package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/socks5"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

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
	return testutils.CountingConn{Conn: conn, Closes: &p.closedConns}, nil
}

func (p *closeProbe) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	p.packets.Add(1)
	pc, err := p.Network.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return countingPacket{pc, &p.closedPackets, p.packetClosed}, nil
}

// chain is the socks5 or socks5h layer over tcp at address.
func chain(scheme, address string, opts permuteproxy.Options) permuteproxy.Chain {
	return permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: scheme, Options: opts}}, Endpoint: permuteproxy.Endpoint{Network: "tcp", Address: address}}
}

// server builds a socks5 server over a loopback tcp listener whose address it sends to bound.
func server(t *testing.T, upstream permuteproxy.Network, opts permuteproxy.Options, bound chan<- net.Addr) permuteproxy.Server {
	t.Helper()
	base := permuteproxy.NetworkFuncs{ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}}
	srv, err := permuteproxy.ServerEngine{Base: base, Upstream: upstream}.Server(chain("socks5", "127.0.0.1:0", opts))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// serve runs a socks5 server on a loopback tcp listener and returns its address.
func serve(t *testing.T, upstream permuteproxy.Network, opts permuteproxy.Options) string {
	t.Helper()
	bound := make(chan net.Addr, 1)
	srv := server(t, upstream, opts, bound)
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
	scheme := "socks5h"
	if resolve {
		scheme = "socks5"
	}
	n, err := permuteproxy.ClientEngine{Base: base, Local: base}.Client(chain(scheme, address, opts))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAssociationCloseEndsControlAndSocket(t *testing.T) {
	upstream := newProbe(testutils.System{})
	addr := serve(t, upstream, nil)
	base := newProbe(testutils.System{})
	n := dialer(t, base, addr, nil, true)
	peer := testutils.UDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := n.DialContext(ctx, "udp", peer.String())
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
			upstream := newProbe(testutils.System{})
			addr := serve(t, upstream, tt.server)
			base := newProbe(testutils.System{})
			if tt.noSocket {
				base.Network = permuteproxy.NetworkFuncs{
					DialContextFunc:  testutils.System{}.DialContext,
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
	base := newProbe(testutils.System{})
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
	addr := serve(t, newProbe(testutils.System{}), nil)
	base := newProbe(testutils.System{})
	n := dialer(t, base, addr, nil, true)
	peer := testutils.UDPEcho(t)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := n.DialContext(ctx, "udp", peer.String())
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
			upstream := newProbe(testutils.System{})
			bound := make(chan net.Addr, 1)
			srv := server(t, upstream, nil, bound)
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
			base := newProbe(testutils.System{})
			n := dialer(t, base, addr.String(), nil, true)
			peer := testutils.UDPEcho(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := n.DialContext(ctx, "udp", peer.String())
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

func TestAssociationConcurrentIO(t *testing.T) {
	addr := serve(t, newProbe(testutils.System{}), nil)
	n := dialer(t, newProbe(testutils.System{}), addr, nil, true)
	peer := testutils.UDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := n.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	const writers, perWriter, readers = 4, 25, 4
	total := writers * perWriter
	// Distinct payloads of distinct lengths, so a datagram assembled or parsed in a shared buffer
	// while another one is in flight shows up as unknown, missing or duplicated.
	payload := func(w, i int) string {
		return fmt.Sprintf("w%d-%02d-%s", w, i, strings.Repeat("x", 1+(w*perWriter+i)%64))
	}
	var writeWG sync.WaitGroup
	writeErrs := make(chan error, total)
	for w := 0; w < writers; w++ {
		writeWG.Add(1)
		go func(w int) {
			defer writeWG.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := pc.WriteTo([]byte(payload(w, i)), peer); err != nil {
					writeErrs <- err
					return
				}
			}
		}(w)
	}
	got := make(chan string, total)
	readErrs := make(chan error, readers)
	var readWG sync.WaitGroup
	for r := 0; r < readers; r++ {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			buf := make([]byte, 4096)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					readErrs <- err
					return
				}
				if from.String() != peer.String() {
					readErrs <- fmt.Errorf("datagram from %v, want %v", from, peer)
					return
				}
				got <- string(buf[:n])
			}
		}()
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	writeWG.Wait()
	select {
	case err := <-writeErrs:
		t.Fatalf("WriteTo = %v", err)
	default:
	}
	seen := map[string]int{}
	for len(seen) < total {
		select {
		case msg := <-got:
			seen[msg]++
		case err := <-readErrs:
			t.Fatalf("ReadFrom = %v after %d of %d datagrams", err, len(seen), total)
		}
	}
	// Close alone must release readers blocked in ReadFrom.
	if err := pc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() { readWG.Wait(); close(released) }()
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("Close left readers blocked in ReadFrom")
	}
	for i := 0; i < readers; i++ {
		if err := <-readErrs; isTimeout(err) {
			t.Fatalf("reader ended by the deadline, not by Close: %v", err)
		}
	}
	close(got)
	for msg := range got {
		seen[msg]++
	}
	for w := 0; w < writers; w++ {
		for i := 0; i < perWriter; i++ {
			msg := payload(w, i)
			if seen[msg] != 1 {
				t.Errorf("%q echoed %d times, want 1", msg, seen[msg])
			}
			delete(seen, msg)
		}
	}
	for msg := range seen {
		t.Errorf("unknown datagram %q echoed", msg)
	}
}

// consume reads datagrams into got until ReadFrom fails, as a quic endpoint does, then reports why.
func consume(pc net.PacketConn) (got <-chan string, failed <-chan error) {
	gotc, errc := make(chan string, 64), make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				errc <- err
				return
			}
			gotc <- string(buf[:n])
		}
	}()
	return gotc, errc
}

// stray sends payload to pc's socket from a source that is not the relay.
func stray(t *testing.T, pc net.PacketConn, payload string) {
	t.Helper()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if _, err := raw.WriteTo([]byte(payload), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatal(err)
	}
}

func TestAssociationSkipsStrayDatagrams(t *testing.T) {
	addr := serve(t, newProbe(testutils.System{}), nil)
	n := dialer(t, newProbe(testutils.System{}), addr, nil, true)
	peer := testutils.UDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := n.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	got, failed := consume(pc)
	stray(t, pc, "\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x09stray")
	stray(t, pc, "x")
	if _, err := pc.WriteTo([]byte("ping"), peer); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if msg != "ping" {
			t.Fatalf("ReadFrom yielded %q, want only the echoed datagram", msg)
		}
	case err := <-failed:
		t.Fatalf("ReadFrom = %v after a stray datagram, want it skipped", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the echoed datagram was never read")
	}
	// The socket's own errors still surface: the deadline ends the loop and reads work once cleared.
	pc.SetReadDeadline(time.Now())
	select {
	case err := <-failed:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ReadFrom = %v, want the deadline error", err)
		}
	case msg := <-got:
		t.Fatalf("ReadFrom yielded %q at the deadline", msg)
	case <-time.After(5 * time.Second):
		t.Fatal("the deadline did not end ReadFrom")
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo([]byte("again"), peer); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "again" || from.String() != peer.String() {
		t.Fatalf("ReadFrom after the deadline = %q from %v, %v", buf[:n], from, err)
	}
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
	addr := serve(t, newProbe(testutils.System{}), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := newProbe(testutils.System{})
	if conn, err := dialer(t, base, addr, nil, true).DialContext(ctx, "udp", "proxy.invalid:9"); err == nil {
		conn.Close()
		t.Fatal("socks5 dialed a name that does not resolve")
	}
	if lookups.Load() == 0 || base.dials.Load() != 0 {
		t.Fatalf("socks5: %d lookups, %d control conns; want a local lookup before any conn", lookups.Load(), base.dials.Load())
	}
	lookups.Store(0)
	base = newProbe(testutils.System{})
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

// answerDNS answers one query on a DNS-over-TCP conn: an A query for name gets 127.0.0.1, any other no record.
func answerDNS(conn net.Conn, name string) {
	defer conn.Close()
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}
	end, labels := 12, []string{}
	for query[end] != 0 {
		labels = append(labels, string(query[end+1:end+1+int(query[end])]))
		end += 1 + int(query[end])
	}
	// The reply keeps the ID and question and sets recursion available, so no record is a final answer.
	reply := append([]byte{query[0], query[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, query[12:end+5]...)
	if strings.Join(labels, ".") == name && binary.BigEndian.Uint16(query[end+1:]) == 1 {
		reply[7] = 1
		reply = append(reply, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
	conn.Write(append(size[:], reply...))
}

func TestUDPDialDefaultPeer(t *testing.T) {
	var lookups atomic.Int32
	stubResolver(t, func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		client, server := net.Pipe()
		go answerDNS(server, "echo.test")
		return client, nil
	})
	addr := serve(t, newProbe(testutils.System{}), nil)
	port := strconv.Itoa(testutils.UDPEcho(t).(*net.UDPAddr).Port)
	ip, name := net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("echo.test", port)
	tests := []struct {
		name         string
		resolve      bool
		target, peer string
		udpAddr      bool // the default peer is a *net.UDPAddr
		dialLookup   bool // the client looked the name up while dialing
		proxyLookup  bool // the proxy looked up the name its datagrams carried
	}{
		{"socks5 ip", true, ip, ip, true, false, false},
		{"socks5 name", true, name, ip, true, true, false},
		{"socks5h ip", false, ip, ip, true, false, false},
		{"socks5h name", false, name, name, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookups.Store(0)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := dialer(t, newProbe(testutils.System{}), addr, nil, tt.resolve).DialContext(ctx, "udp", tt.target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			remote := conn.RemoteAddr()
			if _, ok := remote.(*net.UDPAddr); remote.String() != tt.peer || ok != tt.udpAddr {
				t.Fatalf("RemoteAddr() = %T %v, want %v as a *net.UDPAddr: %v", remote, remote, tt.peer, tt.udpAddr)
			}
			dialed := lookups.Load()
			if (dialed > 0) != tt.dialLookup {
				t.Fatalf("%d lookups while dialing", dialed)
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ping" {
				t.Fatalf("Read = %q, %v", buf[:n], err)
			}
			if proxied := lookups.Load() - dialed; (proxied > 0) != tt.proxyLookup {
				t.Fatalf("%d lookups after the dial", proxied)
			}
		})
	}
}

func TestSchemesTakeOnlyCredentials(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		c, err := permuteproxy.ParseURI(scheme + "://u:p@127.0.0.1:1080")
		if err != nil {
			t.Fatal(err)
		}
		if want := (permuteproxy.Options{"username": "u", "password": "p"}); !maps.Equal(c.Layers[0].Options, want) {
			t.Fatalf("%s credentials = %v, want %v", scheme, c.Layers[0].Options, want)
		}
		if _, err := permuteproxy.ParseURI(scheme + "://127.0.0.1:1080?x=1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Fatalf("%s with option x = %v, want ErrInvalidChain", scheme, err)
		}
	}
}

func TestClientRefusesUnlistedNetworks(t *testing.T) {
	for _, resolve := range []bool{true, false} {
		base := newProbe(testutils.System{})
		n := dialer(t, base, "127.0.0.1:1", nil, resolve)
		ctx := context.Background()
		if _, err := n.DialContext(ctx, "unix", "proxy.sock"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("DialContext(unix) = %v, want ErrUnsupported", err)
		}
		if _, err := n.ListenPacket(ctx, "unixgram", "proxy.sock"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("ListenPacket(unixgram) = %v, want ErrUnsupported", err)
		}
		if _, err := n.Listen(ctx, "tcp", "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("Listen(tcp) = %v, want ErrUnsupported", err)
		}
		if base.dials.Load() != 0 || base.packets.Load() != 0 {
			t.Fatalf("base dials %d packets %d, want none", base.dials.Load(), base.packets.Load())
		}
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

type accepted struct {
	conn net.Conn
	err  error
}

func TestASecondRunBindsTheAddressTheFirstBound(t *testing.T) {
	target := testutils.ReservePort(t)
	binds := make(chan error, 1)
	upstream := permuteproxy.NetworkFuncs{ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := testutils.System{}.Listen(ctx, network, address)
		binds <- err
		return ln, err
	}}
	bound := make(chan net.Addr, 1)
	srv := server(t, upstream, nil, bound)
	defer srv.Close()
	for run := 1; run <= 2; run++ {
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.Run(ctx) }()
		dialer := &socks5.Dialer{ProxyNetwork: "tcp", ProxyAddress: testutils.Wait(t, bound, "the proxy's listener").String()}
		bind, err := dialer.Listen(ctx, "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		replies := make(chan accepted, 1)
		go func() {
			conn, err := bind.Accept()
			replies <- accepted{conn, err}
		}()
		if err := testutils.Wait(t, binds, "the BIND listen"); err != nil {
			t.Fatalf("run %d: BIND listen on %s = %v", run, target, err)
		}
		peer, err := net.Dial("tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		reply := testutils.Wait(t, replies, "the BIND reply")
		if reply.err != nil {
			t.Fatalf("run %d: BIND = %v", run, reply.err)
		}
		if got, want := reply.conn.RemoteAddr().String(), peer.LocalAddr().String(); got != want {
			t.Fatalf("run %d: BIND accepted %s, want %s", run, got, want)
		}
		reply.conn.Close()
		peer.Close()
		stop()
		if err := testutils.Wait(t, done, "Run"); err != nil {
			t.Fatalf("run %d: Run = %v", run, err)
		}
	}
}

// notifyingListener closes closed on its first Close.
type notifyingListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *notifyingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func TestABindListenerOpenedAfterServeReturnedIsClosed(t *testing.T) {
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := permuteproxy.NetworkFuncs{ListenFunc: func(_ context.Context, network, address string) (net.Listener, error) {
		close(entered)
		<-release
		ln, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { ln.Close() })
		return &notifyingListener{Listener: ln, closed: closed}, nil
	}}
	funcs, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(context.Background(), ln, upstream) }()
	bind, err := (&socks5.Dialer{ProxyNetwork: "tcp", ProxyAddress: ln.Addr().String()}).Listen(context.Background(), "tcp", testutils.ReservePort(t))
	if err != nil {
		t.Fatal(err)
	}
	go bind.Accept()
	testutils.Wait(t, entered, "the BIND listen")
	ln.Close()
	testutils.Wait(t, done, "Serve")
	close(release)
	testutils.Wait(t, closed, "the close of a BIND listener opened after Serve returned")
}

func TestABindTheUpstreamCannotListenForIsRefused(t *testing.T) {
	upstream := permuteproxy.NetworkFuncs{ListenFunc: func(context.Context, string, string) (net.Listener, error) {
		return nil, errors.New("no listener")
	}}
	funcs, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(context.Background(), ln, upstream) }()
	bind, err := (&socks5.Dialer{ProxyNetwork: "tcp", ProxyAddress: ln.Addr().String()}).Listen(context.Background(), "tcp", testutils.ReservePort(t))
	if err != nil {
		t.Fatal(err)
	}
	replies := make(chan accepted, 1)
	go func() {
		conn, err := bind.Accept()
		replies <- accepted{conn, err}
	}()
	if reply := testutils.Wait(t, replies, "the BIND reply"); reply.err == nil {
		reply.conn.Close()
		t.Fatal("BIND succeeded without a listener")
	}
	ln.Close()
	testutils.Wait(t, done, "Serve")
}
