package permuteproxy

import (
	"context"
	"errors"
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
