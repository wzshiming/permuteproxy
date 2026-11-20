package quic_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

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

// reaches fails unless what c writes arrives on the next conn accepted hands over.
func reaches(t *testing.T, c net.Conn, accepted <-chan net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	srv := recv(t, accepted, "accept")
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(srv, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestUnspecifiedPeerIsTheLoopbackOfTheSocketsFamily(t *testing.T) {
	k := issue(t)
	t.Run("quic://:port", func(t *testing.T) {
		ln, err := build(t, permuteproxy.Engine{}, quicChain(":0", k.server)).Listen(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		accepted := accept(t, ln)
		reaches(t, dial(t, build(t, permuteproxy.Engine{}, quicChain(":"+port, k.client))), accepted)
	})
	funcs, err := quic.NewAdapter(k.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := funcs.BeforeDial(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, socket, listen string
		peer                 net.IP
	}{
		{"ipv4 socket, empty host", "0.0.0.0:0", "127.0.0.1:0", nil},
		{"ipv4 socket, 0.0.0.0", "0.0.0.0:0", "127.0.0.1:0", net.IPv4zero},
		{"ipv6 socket, empty host", "[::]:0", "[::1]:0", nil},
		{"ipv6 socket, ::", "[::]:0", "[::1]:0", net.IPv6unspecified},
	} {
		t.Run(c.name, func(t *testing.T) {
			mem := newMemNet()
			ln, err := build(t, permuteproxy.Engine{Base: mem}, quicChain(c.listen, k.server)).Listen(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			accepted := accept(t, ln)
			pc, err := mem.ListenPacket(context.Background(), "udp", c.socket)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			peer := &net.UDPAddr{IP: c.peer, Port: ln.Addr().(*net.UDPAddr).Port}
			conn, err := funcs.Stream.Client(ctx, netutils.WrapPacket(pc, peer))
			if err != nil {
				t.Fatalf("Client from %s to %v = %v", c.socket, peer, err)
			}
			t.Cleanup(func() { conn.Close() })
			reaches(t, conn, accepted)
		})
	}
}
