package permuteproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
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

func TestAdapterClosesCarrierOnFailure(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: recordedCloses}
	for scheme := range failingLinks {
		t.Run(scheme, func(t *testing.T) {
			tr, err := e.Transport(mk("", scheme))
			if err != nil {
				t.Fatal(err)
			}
			plane := tr.Planes()
			if _, err := tr.Dial(ctx, plane); !errors.Is(err, errLink) {
				t.Fatalf("Dial() = %v, want the link error", err)
			}
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

func TestAdaptAndNewAdapterCoexist(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{Base: &fakeNet{name: "base"}}.Transport(mk("tcp", "test-snappy", "wide", "test-tls"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-tls.new", "wide.adapt stream", "test-snappy.new")
	if tr.Planes() != Stream {
		t.Fatalf("Planes() = %v, want stream", tr.Planes())
	}
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "wide.dial stream", "test-snappy.client", "wide.listen", "test-snappy.listener")
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
		{Engine{}, mk("fakenet", "test-socks5"), "impl"},
		{Engine{}, mk("tcp", "test-socks5"), "native"},
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
	assertCalls(t, "test-socks5.listenpacket stream local=base udp6 :0")
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
	conn, err := n.DialContext(ctx, "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-peer.peer udp "+address, "test-peer.listenpacket udp :0")
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
		if _, err := n.Listen(ctx, network, "x:1"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Listen(%q) = %v, want ErrUnsupported", network, err)
		}
	}
	assertCalls(t)
}

func TestClientAndNewClientCoexist(t *testing.T) {
	calls = nil
	ctx := context.Background()
	declared, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-http"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := Engine{Base: declared}.Client(mk("", "test-legacy"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-http.new", "test-legacy.client stream|packet")
	if _, err := legacy.DialContext(ctx, "tcp4", "x:1"); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-http.dial stream tcp4 x:1")
	if _, err := legacy.Listen(ctx, "tcp", "x:1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Listen through the Client-style hop = %v, want the declared client's ErrUnsupported", err)
	}
	if _, err := legacy.DialContext(ctx, "udp", "x:1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("udp dial through the Client-style hop = %v, want the declared client's ErrUnsupported", err)
	}
	assertCalls(t)
}
