package quic_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/protocols/quic"
)

// unsent fails unless s was closed once without sending a datagram.
func unsent(t *testing.T, s *memSocket, what string) {
	t.Helper()
	if w, c := s.writes.Load(), s.closes.Load(); w != 0 || c != 1 {
		t.Fatalf("%s carrier wrote %d datagrams and closed %d times, want none and once", what, w, c)
	}
}

func TestUnixgramCarrierIsUnsupported(t *testing.T) {
	mem := newMemNet()
	k := issue(t)
	over := func(opts permuteproxy.Options) permuteproxy.Transport {
		return build(t, permuteproxy.Engine{Base: mem}, permuteproxy.Chain{
			Layers:   []permuteproxy.Layer{{Scheme: "quic", Options: opts}},
			Endpoint: permuteproxy.Endpoint{Network: "unixgram", Address: "/proxy.sock"},
		})
	}
	if _, err := over(k.client).Dial(context.Background(), permuteproxy.Stream); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Dial over unixgram = %v, want ErrUnsupported", err)
	}
	unsent(t, mem.socket(t, 0), "dialed")
	if _, err := over(k.server).Listen(context.Background()); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Listen over unixgram = %v, want ErrUnsupported", err)
	}
	unsent(t, mem.socket(t, 1), "listened")
}

func TestPeerThatIsNotIPPortIsUnsupported(t *testing.T) {
	funcs, err := quic.NewAdapter(permuteproxy.Options{"tls_skip_verify": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if err := funcs.BeforeDial(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []net.Addr{&net.UnixAddr{Name: "/proxy.sock", Net: "unixgram"}, netutils.NewNetAddr("udp", "localhost:1")} {
		mem := newMemNet()
		pc, err := mem.ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := funcs.Stream.Client(context.Background(), netutils.WrapPacket(pc, peer)); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("Client to %v = %v, want ErrUnsupported", peer, err)
		}
		unsent(t, mem.socket(t, 0), peer.String())
	}
}
