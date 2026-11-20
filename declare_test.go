package permuteproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

func TestAdapterPairs(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		scheme string
		plane  Plane
		dial   []string
		listen []string
	}{
		{"test-tls", Stream, []string{"base.dial tcp 127.0.0.1:1", "test-tls.client"}, []string{"base.listen tcp 127.0.0.1:1", "test-tls.listener"}},
		{"test-quic", Stream, []string{"base.listenpacket udp :0", "test-quic.client"}, []string{"base.listenpacket udp 127.0.0.1:1", "test-quic.packetlistener"}},
		{"test-dtls", Packet, []string{"base.listenpacket udp :0", "test-dtls.client"}, []string{"base.listenpacket udp 127.0.0.1:1", "test-dtls.packetconn"}},
		{"test-uot", Packet, []string{"base.dial tcp 127.0.0.1:1", "test-uot.client"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			tr, err := e.Transport(mk("", tt.scheme))
			if err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.scheme+".new")
			if tr.Planes() != tt.plane {
				t.Fatalf("Planes() = %v, want %v", tr.Planes(), tt.plane)
			}
			if _, err := tr.Dial(ctx, tt.plane); err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.dial...)
			if tt.plane == Stream {
				_, err = tr.Listen(ctx)
			} else {
				_, err = tr.ListenPacket(ctx)
			}
			if tt.listen == nil && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("listening without a server form = %v, want ErrUnsupported", err)
			}
			if tt.listen != nil && err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.listen...)
		})
	}
}

func TestDgramDeclaration(t *testing.T) {
	spec, ok := lookupLayer("dgram")
	if !ok {
		t.Fatal("dgram is not registered")
	}
	if spec.Kind != KindAdapter || spec.Requires != Stream || spec.Provides != Packet || spec.Preserves != 0 || spec.Lossy != Packet {
		t.Fatalf("dgram declares kind %v, requires %v, provides %v, preserves %v, lossy %v", spec.Kind, spec.Requires, spec.Provides, spec.Preserves, spec.Lossy)
	}
	if err := parse(t, "dgram+cmd:nc host 1").Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseURI("test-dtls+dgram+cmd:nc host 1"); !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), "datagram boundaries") {
		t.Fatalf("ParseURI with Packet required over dgram = %v, want ErrInvalidChain naming datagram boundaries", err)
	}
}

func TestDgramDialsStreamCarrierAsDatagrams(t *testing.T) {
	calls = nil
	ctx := context.Background()
	near, far := net.Pipe()
	defer far.Close()
	peer := netutils.NewNetAddr("cmd", "nc host 1")
	base := NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
		record("base.dial %s %s", network, address)
		return netutils.ConnWithAddr(near, nil, peer), nil
	}}
	tr, err := Engine{Base: base}.Transport(parse(t, "dgram+cmd:nc host 1"))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Planes() != Packet {
		t.Fatalf("Planes() = %v, want packet", tr.Planes())
	}
	conn, err := tr.Dial(ctx, Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertCalls(t, "base.dial cmd nc host 1")
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("dgram conn is not a net.PacketConn")
	}
	if conn.RemoteAddr() != peer {
		t.Fatalf("RemoteAddr() = %v, want the carrier's %v", conn.RemoteAddr(), peer)
	}
	read := make(chan string, 1)
	go func() {
		b := make([]byte, 16)
		n, _ := far.Read(b)
		read <- string(b[:n])
	}()
	if _, err := pc.WriteTo([]byte("ping"), peer); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, read, "carrier read"); got != "ping" {
		t.Fatalf("carrier read %q, want ping", got)
	}
	go far.Write([]byte("pong"))
	buf := make([]byte, 16)
	if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "pong" || from != peer {
		t.Fatalf("ReadFrom = %q from %v, %v; want pong from %v", buf[:n], from, err, peer)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() = %v, want ErrUnsupported", err)
	}
	if _, err := tr.Listen(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Listen() = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
}

func TestAdapterPacketCarrier(t *testing.T) {
	ctx := context.Background()
	for _, network := range []string{"udp", "unixgram"} {
		t.Run(network, func(t *testing.T) {
			calls = nil
			target := datagramPeer(t, network)
			c := Chain{Layers: []Layer{{Scheme: "test-quic"}}, Endpoint: Endpoint{Network: network, Address: target.LocalAddr().String()}}
			tr, err := Engine{}.Transport(c)
			if err != nil {
				t.Fatal(err)
			}
			// test-quic hands its carrier back, so the dialed conn is what its Client received.
			carrier, err := tr.Dial(ctx, Stream)
			if err != nil {
				t.Fatal(err)
			}
			exchange(t, carrier, target)
			closedPacket(t, carrier)
			assertCalls(t, "test-quic.new", "test-quic.client")
		})
	}
}

func TestAdapterPreservesWithoutLink(t *testing.T) {
	calls = nil
	ctx := context.Background()
	held := &net.UDPConn{}
	base := NetworkFuncs{
		DialContextFunc: (&fakeNet{name: "base"}).DialContext,
		ListenPacketFunc: func(_ context.Context, network, address string) (net.PacketConn, error) {
			record("base.listenpacket %s %s", network, address)
			return held, nil
		},
	}
	tr, err := Engine{Base: base}.Transport(mk("", "test-keep"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-keep.new")
	if tr.Planes() != Stream|Packet {
		t.Fatalf("Planes() = %v, want stream|packet", tr.Planes())
	}
	conn, err := tr.Dial(ctx, Packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(net.PacketConn); !ok || conn.RemoteAddr().String() != "127.0.0.1:1" {
		t.Fatalf("Dial(Packet) = %v, want the carrier's own datagram conn to 127.0.0.1:1", conn)
	}
	pc, err := tr.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pc != net.PacketConn(held) {
		t.Fatalf("ListenPacket() = %v, want the carrier's socket unchanged", pc)
	}
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.listenpacket udp :0", "base.listenpacket udp 127.0.0.1:1", "base.dial tcp 127.0.0.1:1", "test-keep.client")
}

func TestAdapterLeavesCarrierToLink(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: recordedCloses}
	for scheme := range failingLinks {
		t.Run(scheme, func(t *testing.T) {
			calls = nil
			tr, err := e.Transport(mk("", scheme))
			if err != nil {
				t.Fatal(err)
			}
			plane := tr.Planes()
			if _, err := tr.Dial(ctx, plane); !errors.Is(err, errLink) {
				t.Fatalf("Dial() = %v, want the link error", err)
			}
			// The failing link closed its carrier, so a second close is the root package's.
			assertCalls(t, "carrier.close")
			if plane == Stream {
				_, err = tr.Listen(ctx)
			} else {
				_, err = tr.ListenPacket(ctx)
			}
			if !errors.Is(err, errLink) {
				t.Fatalf("listening = %v, want the link error", err)
			}
			assertCalls(t, "carrier.close")
		})
	}
	for _, scheme := range []string{"test-tls", "test-quic", "test-dtls"} {
		tr, err := e.Transport(mk("", scheme))
		if err != nil {
			t.Fatal(err)
		}
		plane := tr.Planes()
		if _, err := tr.Dial(ctx, plane); err != nil {
			t.Fatal(err)
		}
		if plane == Stream {
			_, err = tr.Listen(ctx)
		} else {
			_, err = tr.ListenPacket(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	assertCalls(t,
		"test-tls.new", "test-tls.client", "test-tls.listener",
		"test-quic.new", "test-quic.client", "test-quic.packetlistener",
		"test-dtls.new", "test-dtls.client", "test-dtls.packetconn")
}

func TestAdapterHooksRunBeforeCarrier(t *testing.T) {
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		scheme string
		err    error
		dial   []string
		listen []string
	}{
		{"test-hook-ss", nil, []string{"test-hook-ss.beforedial", "base.dial tcp 127.0.0.1:1", "test-hook-ss.client"}, []string{"test-hook-ss.beforelisten", "base.listen tcp 127.0.0.1:1", "test-hook-ss.listener"}},
		{"test-hook-sp", nil, []string{"test-hook-sp.beforedial", "base.listenpacket udp :0", "test-hook-sp.client"}, []string{"test-hook-sp.beforelisten", "base.listenpacket udp 127.0.0.1:1", "test-hook-sp.packetlistener"}},
		{"test-hook-pp", nil, []string{"test-hook-pp.beforedial", "base.listenpacket udp :0", "test-hook-pp.client"}, []string{"test-hook-pp.beforelisten", "base.listenpacket udp 127.0.0.1:1", "test-hook-pp.packetconn"}},
		{"test-hookfail-ss", errHook, []string{"test-hookfail-ss.beforedial"}, []string{"test-hookfail-ss.beforelisten"}},
		{"test-hookfail-sp", errHook, []string{"test-hookfail-sp.beforedial"}, []string{"test-hookfail-sp.beforelisten"}},
		{"test-hookfail-pp", errHook, []string{"test-hookfail-pp.beforedial"}, []string{"test-hookfail-pp.beforelisten"}},
	}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			calls = nil
			tr, err := e.Transport(mk("", tt.scheme))
			if err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.scheme+".new")
			plane := tr.Planes()
			if _, err := tr.Dial(ctx, plane); err != tt.err {
				t.Fatalf("Dial() = %v, want %v unchanged", err, tt.err)
			}
			assertCalls(t, tt.dial...)
			if plane == Stream {
				_, err = tr.Listen(ctx)
			} else {
				_, err = tr.ListenPacket(ctx)
			}
			if err != tt.err {
				t.Fatalf("listening = %v, want %v unchanged", err, tt.err)
			}
			assertCalls(t, tt.listen...)
		})
	}
}

func TestAdapterHooksSkipAPlanePassedThrough(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		scheme string
		plane  Plane // the plane passed through
		calls  []string
	}{
		{"test-hook-keep", Packet, []string{"base.listenpacket udp :0", "base.listenpacket udp 127.0.0.1:1"}},
		{"test-hook-keep-stream", Stream, []string{"base.dial tcp 127.0.0.1:1", "base.listen tcp 127.0.0.1:1"}},
	}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			tr, err := Engine{Base: &fakeNet{name: "base"}}.Transport(mk("", tt.scheme))
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			if _, err := tr.Dial(ctx, tt.plane); err != nil {
				t.Fatal(err)
			}
			if tt.plane == Stream {
				_, err = tr.Listen(ctx)
			} else {
				_, err = tr.ListenPacket(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.calls...)
		})
	}
}

func TestAdapterRefusesMissingFunctions(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	for _, scheme := range []string{"test-bare-ss", "test-bare-sp", "test-bare-pp", "test-bare-ps"} {
		t.Run(scheme, func(t *testing.T) {
			tr, err := e.Transport(mk("", scheme))
			if err != nil {
				t.Fatal(err)
			}
			plane := tr.Planes()
			_, dialErr := tr.Dial(ctx, plane)
			var listenErr error
			if plane == Stream {
				_, listenErr = tr.Listen(ctx)
			} else {
				_, listenErr = tr.ListenPacket(ctx)
			}
			if !errors.Is(dialErr, ErrUnsupported) || !errors.Is(listenErr, ErrUnsupported) {
				t.Fatalf("dial = %v, listen = %v; want ErrUnsupported for both", dialErr, listenErr)
			}
			assertCalls(t)
		})
	}
}

func TestAdapterRejectsDeclarations(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	schemes := []string{"niladapter", "test-broken"}
	for name := range uncovered {
		schemes = append(schemes, name)
	}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			c := mk("", scheme)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Transport(c); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Transport() = %v, want ErrInvalidChain", err)
			}
			assertCalls(t)
		})
	}
	if _, err := e.Transport(mk("", "test-broken")); !errors.Is(err, errDeclare) {
		t.Fatalf("Transport() = %v, want the NewAdapter error kept", err)
	}
	c := mk("", "test-http", "test-bad-missing")
	if _, err := e.Client(c); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("Client() = %v, want ErrInvalidChain", err)
	}
	if _, err := e.Server(c); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("Server() = %v, want ErrInvalidChain", err)
	}
	assertCalls(t)
}

func TestAdapterClosesOnce(t *testing.T) {
	calls = nil
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}}
	tests := []struct {
		chain Chain
		want  []string
	}{
		{mk("tcp", "closable"), []string{"closable.close"}},
		{mk("tcp", "test-tls", "closable"), []string{"closable.close"}},
		{mk("tcp", "closable", "closable"), []string{"closable.close", "closable.close"}},
	}
	for _, tt := range tests {
		tr, err := e.Transport(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		for i := 0; i < 2; i++ {
			if err := tr.(io.Closer).Close(); err != nil {
				t.Fatal(err)
			}
		}
		assertCalls(t, tt.want...)
	}
}

func TestClientDialsStream(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-socks5", "test-quic"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-quic.new", "test-socks5.new")
	for _, network := range []string{"tcp", "tcp4", "tcp6"} {
		if _, err := n.DialContext(ctx, network, "x:1"); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, "test-socks5.dial stream "+network+" x:1")
	}
}

func TestClientAdmitsListedNetworks(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		uri     string
		allowed map[string]string
		refused []string
	}{
		{
			"test-http://127.0.0.1:1",
			map[string]string{
				"dial tcp":  "test-http.dial stream tcp x:1",
				"dial tcp4": "test-http.dial stream tcp4 x:1",
				"dial tcp6": "test-http.dial stream tcp6 x:1",
			},
			[]string{"dial unix", "dial fakenet", "dial udp", "dial udp4", "dial unixgram", "dial bogus", "dial ", "listenpacket udp", "listenpacket tcp"},
		},
		{
			"test-ss+udp://127.0.0.1:1",
			map[string]string{
				"dial udp":              "test-ss.listenpacket packet local=base udp :0",
				"dial udp4":             "test-ss.listenpacket packet local=base udp :0",
				"listenpacket udp6":     "test-ss.listenpacket packet local=base udp6 x:1",
				"listenpacket unixgram": "test-ss.listenpacket packet local=base unixgram x:1",
			},
			[]string{"dial tcp", "dial tcp6", "dial unixgram", "listenpacket tcp", "listenpacket bogus"},
		},
		{
			"test-ss://127.0.0.1:1",
			map[string]string{
				"dial tcp4":        "test-ss.dial stream|packet tcp4 x:1",
				"dial udp6":        "test-ss.listenpacket stream|packet local=base udp :0",
				"listenpacket udp": "test-ss.listenpacket stream|packet local=base udp x:1",
			},
			[]string{"dial unix", "dial fakenet", "listenpacket unix", "listenpacket tcp4"},
		},
		{"test-peer://127.0.0.1:1", nil, []string{"listenpacket unixgram", "dial unixgram", "dial tcp"}},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			n, err := e.Client(parse(t, tt.uri))
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			for _, op := range tt.refused {
				if err := netOp(ctx, n, op); !errors.Is(err, ErrUnsupported) {
					t.Fatalf("%q = %v, want ErrUnsupported", op, err)
				}
				assertCalls(t)
			}
			for op, want := range tt.allowed {
				if err := netOp(ctx, n, op); err != nil {
					t.Fatalf("%q = %v", op, err)
				}
				assertCalls(t, want)
			}
		})
	}
}

func TestClientListensPacketThroughLocal(t *testing.T) {
	calls = nil
	ctx := context.Background()
	base := &fakeNet{name: "base"}
	tests := []struct {
		engine Engine
		chain  Chain
		local  string
	}{
		{Engine{Base: base}, mk("fakenet", "test-socks5"), "base"},
		{Engine{}, mk("fakenet", "test-socks5"), "default"},
		{Engine{}, mk("tcp", "test-socks5"), "default"},
	}
	for _, tt := range tests {
		n, err := tt.engine.Client(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		if _, err := n.ListenPacket(ctx, "udp4", "x:1"); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, "test-socks5.listenpacket stream local="+tt.local+" udp4 x:1")
	}
}

func TestClientDerivesUDPDial(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-socks5"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := n.DialContext(ctx, "unixgram", "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unixgram dial = %v, want ErrUnsupported outside the udp family", err)
	}
	assertCalls(t)
	conn, err := n.DialContext(ctx, "udp6", "unresolvable.invalid:1")
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-socks5.listenpacket stream local=base udp :0")
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatal("udp conn is not a net.PacketConn")
	}
	if remote := conn.RemoteAddr(); remote.Network() != "udp" || remote.String() != "unresolvable.invalid:1" {
		t.Fatalf("RemoteAddr() = %s %v, want the udp address carried verbatim", remote.Network(), remote)
	}
}

func TestClientAsksPeerOfUDPDial(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{}.Client(mk("", "test-peer"))
	if err != nil {
		t.Fatal(err)
	}
	target := datagramPeer(t, "udp")
	address := target.LocalAddr().String()
	conn, err := n.DialContext(ctx, "udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-peer.peer udp4 "+address, "test-peer.listenpacket udp :0")
	exchange(t, conn, target)
	closedPacket(t, conn)
	if _, err := n.DialContext(ctx, "udp", "x"); err == nil {
		t.Fatal("udp dial to an address Peer refuses succeeded")
	}
	assertCalls(t, "test-peer.peer udp x")
}

func TestClientRefusesListen(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-ss"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	for _, network := range []string{"tcp", "tcp6", "unix", "fakenet", "udp", "bogus"} {
		if _, err := n.Listen(ctx, network, "x:1"); !errors.Is(err, ErrUnsupported) || err.Error() != "listen "+network+": unsupported" {
			t.Fatalf("Listen(%q) = %v, want ErrUnsupported", network, err)
		}
	}
	assertCalls(t)
}

func TestClientRejectsDeclarations(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	schemes := []string{"nilproxy", "test-client-broken"}
	for name := range uncoveredClients {
		schemes = append(schemes, name)
	}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			if _, err := e.Client(mk("", scheme)); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Client() = %v, want ErrInvalidChain", err)
			}
			assertCalls(t)
		})
	}
	if _, err := e.Client(mk("", "test-client-broken")); !errors.Is(err, errDeclare) {
		t.Fatalf("Client() = %v, want the NewClient error kept", err)
	}
}

func TestClientClosesOnce(t *testing.T) {
	calls = nil
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}}
	tests := []struct {
		chain Chain
		want  []string
	}{
		{mk("tcp", "closableproxy"), []string{"closableproxy.close"}},
		{mk("tcp", "closableproxy", "closable"), []string{"closableproxy.close", "closable.close"}},
		{mk("tcp", "test-http", "closable"), []string{"closable.close"}},
	}
	for _, tt := range tests {
		n, err := e.Client(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		for i := 0; i < 2; i++ {
			if err := n.(io.Closer).Close(); err != nil {
				t.Fatal(err)
			}
		}
		assertCalls(t, tt.want...)
	}
}

func TestClientReportsLossyFromSpec(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		scheme string
		lossy  map[string]bool
	}{
		{"test-lossy-proxy", map[string]bool{"udp": true, "udp6": true, "unixgram": true, "tcp": false, "unix": false, "bogus": false}},
		{"test-socks5", map[string]bool{"udp": false, "unixgram": false, "tcp": false}},
	}
	for _, tt := range tests {
		n, err := e.Client(mk("", tt.scheme))
		if err != nil {
			t.Fatal(err)
		}
		l, ok := n.(LossyNetwork)
		if !ok {
			t.Fatalf("Client of %s is not a LossyNetwork", tt.scheme)
		}
		for network, want := range tt.lossy {
			if got := l.Lossy(network); got != want {
				t.Fatalf("Client of %s: Lossy(%q) = %v, want %v", tt.scheme, network, got, want)
			}
		}
	}
}

// recv waits for a value from ch, failing the test after five seconds.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen", what)
		var zero T
		return zero
	}
}

func TestServerBindFailureReleasesCarriers(t *testing.T) {
	calls = nil
	base := NetworkFuncs{
		ListenFunc:       func(context.Context, string, string) (net.Listener, error) { return closeListener{}, nil },
		ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) { return nil, errLink },
	}
	srv, err := Engine{Base: base}.Server(mk("", "test-ss"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := srv.Run(context.Background()); !errors.Is(err, errLink) {
		t.Fatalf("Run() = %v, want the packet bind error", err)
	}
	assertCalls(t, "carrier.close")
}

func TestServerBindsRequiredOrPreservedPlanes(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		chain Chain
		serve []string
	}{
		{mk("", "test-socks5", "test-keep"), []string{"base.listen tcp 127.0.0.1:1", "test-keep.listener", "test-socks5.serve upstream=default"}},
		{mk("", "test-ss", "test-keep"), []string{"base.listen tcp 127.0.0.1:1", "test-keep.listener", "base.listenpacket udp 127.0.0.1:1", "test-ss.serve upstream=default", "test-ss.servepacket upstream=default"}},
	}
	for _, tt := range tests {
		srv, err := e.Server(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		assertRun(t, srv, tt.serve...)
	}
}

func TestServerFirstReturnCancelsOther(t *testing.T) {
	errServe := errors.New("serve failed")
	for _, first := range []Plane{Stream, Packet} {
		t.Run(first.String(), func(t *testing.T) {
			exits := make(chan error, 2)
			serve := func(ctx context.Context, plane Plane) error {
				err := errServe
				if plane != first {
					<-ctx.Done()
					err = ctx.Err()
				}
				exits <- err
				return err
			}
			funcs := &ServerFuncs{
				Serve:       func(ctx context.Context, _ net.Listener, _ Network) error { return serve(ctx, Stream) },
				ServePacket: func(ctx context.Context, _ net.PacketConn, _ Network) error { return serve(ctx, Packet) },
			}
			// The serves belong to this test, so the declared server is assembled directly.
			inner := &bound{network: &fakeNet{name: "base"}, stream: "tcp", packet: "udp", address: "x:1"}
			srv, err := declaredServer(0, Stream|Packet, funcs, nil).server(inner, native, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := srv.Run(context.Background()); !errors.Is(err, errServe) {
				t.Fatalf("Run() = %v, want the error of the serve that returned first", err)
			}
			for _, want := range []error{errServe, context.Canceled} {
				select {
				case got := <-exits:
					if !errors.Is(got, want) {
						t.Fatalf("serve ended with %v, want %v", got, want)
					}
				default:
					t.Fatal("Run returned before both serves ended")
				}
			}
		})
	}
}

func TestServerStopReleasesCarriers(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			addrs := make(chan net.Addr, 1)
			accepted := make(chan struct{}, 1)
			ends := make(chan error, 2)
			funcs := &ServerFuncs{
				Serve: func(_ context.Context, ln net.Listener, _ Network) error {
					addrs <- ln.Addr()
					conn, err := ln.Accept()
					if err != nil {
						return err
					}
					accepted <- struct{}{}
					_, err = conn.Read(make([]byte, 1))
					ends <- err
					return err
				},
				ServePacket: func(_ context.Context, pc net.PacketConn, _ Network) error {
					_, _, err := pc.ReadFrom(make([]byte, 1))
					ends <- err
					return err
				},
			}
			inner := &bound{network: native, stream: "tcp", packet: "udp", address: "127.0.0.1:0"}
			srv, err := declaredServer(0, Stream|Packet, funcs, nil).server(inner, native, Options{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- srv.Run(ctx) }()
			addr := recv(t, addrs, "bind")
			client, err := net.Dial("tcp", addr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			recv(t, accepted, "accept")
			if stop == "cancel" {
				cancel()
			} else if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			if err := recv(t, done, "Run returning"); err != nil {
				t.Fatalf("Run() = %v after the stop, want nil", err)
			}
			for i := 0; i < 2; i++ {
				if err := recv(t, ends, "serve read"); err == nil {
					t.Fatal("a serve read its carrier after the stop")
				}
			}
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("client read = %v, want its accepted conn closed by the stop", err)
			}
			if conn, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
				conn.Close()
				t.Fatal("listener still open after the stop")
			}
		})
	}
}

func TestServerRejectsDeclarations(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	schemes := []string{"nilproxy", "test-server-broken"}
	for name := range uncoveredServers {
		schemes = append(schemes, name)
	}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			if _, err := e.Server(mk("", scheme)); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Server() = %v, want ErrInvalidChain", err)
			}
			assertCalls(t)
		})
	}
	if _, err := e.Server(mk("", "test-server-broken")); !errors.Is(err, errDeclare) {
		t.Fatalf("Server() = %v, want the NewServer error kept", err)
	}
}

func TestServerRefusesCarrierWithNothingToBind(t *testing.T) {
	calls = nil
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}}
	lossy := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	for _, tt := range []struct {
		name   string
		engine Engine
		chain  Chain
		want   []string
	}{
		{"NewServer over a stream carrier", e, mk("tcp", "test-packet-server", "closable"), []string{"closable.close"}},
		{"NewServer over lossy udp", lossy, mk("udp", "test-ss", "test-counted"), []string{"test-counted.close"}},
		{"NewServer right over lossy udp", lossy, mk("udp", "test-ss"), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls = nil
			if _, err := tt.engine.Server(tt.chain); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("Server() over a carrier with no plane to bind = %v, want ErrUnsupported", err)
			}
			assertCalls(t, tt.want...)
		})
	}
	calls = nil
	srv, err := e.Server(mk("udp", "test-packet-server"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-packet-server.newserver")
	assertRun(t, srv, "base.listenpacket udp 127.0.0.1:1", "test-packet-server.servepacket upstream=default")
}

func TestServerRefusesCarrierLackingARequiredPlane(t *testing.T) {
	name := fresh("test-dual-server")
	RegisterLayer(name, Spec{Kind: KindProxy, Requires: Stream | Packet, Provides: Stream, NewServer: func(Options) (*ServerFuncs, error) {
		record("test-dual-server.newserver")
		return &ServerFuncs{Serve: failServe, ServePacket: failServePacket}, nil
	}})
	// The Base reports udp lossy, so the layer's carrier keeps only its stream.
	e := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	for _, tt := range []struct {
		chain Chain
		want  []string
	}{
		{mk("", name), nil},
		{mk("", name, "test-counted"), []string{"test-counted.close"}},
	} {
		calls = nil
		if _, err := e.Server(tt.chain); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Server() over a carrier lacking packet = %v, want ErrUnsupported", err)
		}
		assertCalls(t, tt.want...)
	}
}

func TestServerClosesOnce(t *testing.T) {
	calls = nil
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}, Upstream: &closableNet{fakeNet{name: "upstream"}}}
	tests := []struct {
		chain Chain
		want  []string
	}{
		{mk("tcp", "closableserver"), []string{"closableserver.close"}},
		{mk("tcp", "closableserver", "closable"), []string{"closableserver.close", "closable.close"}},
		{mk("tcp", "test-http", "closable"), []string{"closable.close"}},
	}
	for _, tt := range tests {
		srv, err := e.Server(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		for i := 0; i < 2; i++ {
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
		}
		assertCalls(t, tt.want...)
		if err := srv.Run(context.Background()); err != nil {
			t.Fatalf("Run() after Close = %v, want nil", err)
		}
		assertCalls(t)
	}
}
