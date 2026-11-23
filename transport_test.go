package permuteproxy

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestFuncsPlaneGating(t *testing.T) {
	calls = nil
	ctx := context.Background()
	stream := TransportFuncs{
		Plane:            Stream,
		DialFunc:         func(_ context.Context, plane Plane) (net.Conn, error) { record("dial %v", plane); return nil, nil },
		ListenFunc:       func(context.Context) (net.Listener, error) { record("listen"); return nil, nil },
		ListenPacketFunc: func(context.Context) (net.PacketConn, error) { record("listenpacket"); return nil, nil },
	}
	packet, dual := stream, stream
	packet.Plane, dual.Plane = Packet, Stream|Packet
	refused := map[string]func() error{
		"stream dial none":    func() error { _, err := stream.Dial(ctx, 0); return err },
		"stream dial both":    func() error { _, err := stream.Dial(ctx, Stream|Packet); return err },
		"stream dial packet":  func() error { _, err := stream.Dial(ctx, Packet); return err },
		"stream listenpacket": func() error { _, err := stream.ListenPacket(ctx); return err },
		"packet dial stream":  func() error { _, err := packet.Dial(ctx, Stream); return err },
		"packet listen":       func() error { _, err := packet.Listen(ctx); return err },
		"dual dial both":      func() error { _, err := dual.Dial(ctx, Stream|Packet); return err },
		"dual dial none":      func() error { _, err := dual.Dial(ctx, 0); return err },
	}
	for name, op := range refused {
		if err := op(); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want ErrUnsupported", name, err)
		}
		assertCalls(t)
	}
	for _, op := range []func() error{
		func() error { _, err := stream.Dial(ctx, Stream); return err },
		func() error { _, err := stream.Listen(ctx); return err },
		func() error { _, err := packet.Dial(ctx, Packet); return err },
		func() error { _, err := packet.ListenPacket(ctx); return err },
		func() error { _, err := dual.Dial(ctx, Packet); return err },
		func() error { _, err := dual.Listen(ctx); return err },
	} {
		if err := op(); err != nil {
			t.Fatal(err)
		}
	}
	assertCalls(t, "dial stream", "listen", "dial packet", "listenpacket", "dial packet", "listen")
}

func TestBoundDialPacket(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{Base: &fakeNet{name: "base"}}.Transport(parse(t, "udp://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Planes() != Packet {
		t.Fatalf("Planes() = %v, want packet", tr.Planes())
	}
	if _, err := tr.Dial(ctx, Packet); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.listenpacket udp :0")
	if _, err := tr.Dial(ctx, Stream); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Stream) = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
}

func TestLossyCarrierRefusesPacketToLayers(t *testing.T) {
	ctx := context.Background()
	e := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	listen := func(tr Transport) error { _, err := tr.Listen(ctx); return err }
	listenPacket := func(tr Transport) error { _, err := tr.ListenPacket(ctx); return err }
	for _, tt := range []struct {
		name   string
		chain  Chain
		dial   Plane
		listen func(Transport) error // nil where the layer has no server form to refuse
	}{
		{"packet layer", mk("udp", "test-dtls"), Packet, nil},
		{"stream layer", mk("udp", "test-quic"), Stream, listen},
		{"preserved packet", mk("", "test-keep"), Packet, listenPacket},
		{"expression network name", chainOver("test-dtls-udp", "127.0.0.1:1"), Packet, listenPacket},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := e.Transport(tt.chain)
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			if _, err := tr.Dial(ctx, tt.dial); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("Dial(%v) over lossy udp = %v, want ErrUnsupported", tt.dial, err)
			}
			if tt.listen != nil {
				if err := tt.listen(tr); !errors.Is(err, ErrUnsupported) {
					t.Fatalf("listening over lossy udp = %v, want ErrUnsupported", err)
				}
			}
			assertCalls(t)
		})
	}
	tr, err := e.Transport(mk("", "test-keep"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.dial tcp 127.0.0.1:1", "test-keep.client", "base.listen tcp 127.0.0.1:1", "test-keep.listener")
}

func TestLossyNetworkWithoutLayersDialsNormally(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}.Transport(mk("udp"))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Planes() != Packet {
		t.Fatalf("Planes() = %v, want packet", tr.Planes())
	}
	if _, err := tr.Dial(ctx, Packet); err != nil {
		t.Fatalf("Dial(Packet) on a lossy network without layers = %v", err)
	}
	if _, err := tr.ListenPacket(ctx); err != nil {
		t.Fatalf("ListenPacket() on a lossy network without layers = %v", err)
	}
	assertCalls(t, "base.listenpacket udp :0", "base.listenpacket udp 127.0.0.1:1")
}
