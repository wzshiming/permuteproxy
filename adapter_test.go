package permuteproxy

import (
	"context"
	"errors"
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
		{"test-dtls", Packet, []string{"base.listenpacket udp :0", "test-dtls.client"}, nil},
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
	for _, scheme := range []string{"test-tls", "test-quic"} {
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
		"test-quic.new", "test-quic.client", "test-quic.packetlistener")
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
		{"test-hookfail-ss", errHook, []string{"test-hookfail-ss.beforedial"}, []string{"test-hookfail-ss.beforelisten"}},
		{"test-hookfail-sp", errHook, []string{"test-hookfail-sp.beforedial"}, []string{"test-hookfail-sp.beforelisten"}},
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
