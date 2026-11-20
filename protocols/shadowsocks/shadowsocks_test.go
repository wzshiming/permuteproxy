package shadowsocks

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
)

type countingPacket struct {
	net.PacketConn
	closes *atomic.Int32
}

func (c countingPacket) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

func TestSessionsCloseOwnedSockets(t *testing.T) {
	var closes atomic.Int32
	s := &sessions{listen: func(ctx context.Context, network, address string) (net.PacketConn, error) {
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return countingPacket{pc, &closes}, nil
	}}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := s.ListenPacket(ctx, "udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if closes.Load() != 2 {
		t.Fatalf("Close closed %d sockets, want 2", closes.Load())
	}
	late, err := s.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if !errors.Is(err, net.ErrClosed) || late != nil {
		t.Fatalf("ListenPacket after Close = %v, %v; want net.ErrClosed", late, err)
	}
	if closes.Load() != 3 {
		t.Fatalf("late socket left open: %d closes, want 3", closes.Load())
	}
	s.Close()
	if closes.Load() != 3 {
		t.Fatal("second Close reached the sockets again")
	}
}

func chain(t *testing.T, uri string) permuteproxy.Chain {
	t.Helper()
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientRefusesPlaneBeforeIO(t *testing.T) {
	var calls atomic.Int32
	base := permuteproxy.NetworkFuncs{
		DialContextFunc: func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("dialed")
		},
		ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) {
			calls.Add(1)
			return nil, errors.New("bound")
		},
	}
	stream, err := permuteproxy.Engine{Base: base}.Client(chain(t, "ss+tcp://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	dual, err := permuteproxy.Engine{Base: base}.Client(chain(t, "ss://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := stream.DialContext(ctx, "udp", "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(udp) over a stream carrier = %v, want ErrUnsupported", err)
	}
	if _, err := stream.ListenPacket(ctx, "udp", ":0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("ListenPacket over a stream carrier = %v, want ErrUnsupported", err)
	}
	if _, err := dual.DialContext(ctx, "unixgram", "/p"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(unixgram) = %v, want ErrUnsupported", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("base reached %d times for refused planes", calls.Load())
	}
}

var system permuteproxy.Network = permuteproxy.NetworkFuncs{
	DialContextFunc:  (&net.Dialer{}).DialContext,
	ListenFunc:       (&net.ListenConfig{}).Listen,
	ListenPacketFunc: (&net.ListenConfig{}).ListenPacket,
}

// upstreamProbe counts the outgoing sockets a server opens and closes.
type upstreamProbe struct {
	permuteproxy.Network
	packets, closes atomic.Int32
}

func (p *upstreamProbe) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := p.Network.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	p.packets.Add(1)
	return countingPacket{pc, &p.closes}, nil
}

// faultyCarrier is a udp carrier whose ReadFrom reports err instead of a datagram once broken.
type faultyCarrier struct {
	net.PacketConn
	err    error
	broken atomic.Bool
	reads  atomic.Int32
}

func (c *faultyCarrier) ReadFrom(b []byte) (int, net.Addr, error) {
	c.reads.Add(1)
	if c.broken.Load() {
		return 0, nil, c.err
	}
	n, addr, err := c.PacketConn.ReadFrom(b)
	if c.broken.Load() {
		return 0, nil, c.err
	}
	return n, addr, err
}

// fail breaks the carrier and wakes a blocked read, which then reports the error.
func (c *faultyCarrier) fail() {
	c.broken.Store(true)
	c.PacketConn.SetReadDeadline(time.Now())
}

func echo(t *testing.T) net.Addr {
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

func TestPacketServerStopsOnCarrierError(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{"closed", net.ErrClosed},
		{"eof", io.EOF},
		{"custom", errors.New("carrier gone")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			carrier := &faultyCarrier{PacketConn: raw, err: tt.err}
			upstream := &upstreamProbe{Network: system}
			opts := permuteproxy.Options{KeyUsername: "aes-256-gcm", KeyPassword: "p"}
			inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Packet, ListenPacketFunc: func(context.Context) (net.PacketConn, error) { return carrier, nil }}
			srv, err := NewServer(inner, upstream, opts)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.Run(context.Background()) }()
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			n, err := permuteproxy.Engine{Base: system}.Client(chain(t, "ss+udp://aes-256-gcm:p@"+raw.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := n.DialContext(ctx, "udp", echo(t).String())
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
			before := carrier.reads.Load()
			carrier.fail()
			select {
			case err := <-done:
				if !errors.Is(err, tt.err) {
					t.Fatalf("Run = %v, want the carrier error %v", err, tt.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("Run kept serving after the carrier failed; %d reads so far", carrier.reads.Load())
			}
			if got := carrier.reads.Load() - before; got > 1 {
				t.Fatalf("carrier read %d times after failing, want at most 1", got)
			}
			if upstream.closes.Load() != 1 {
				t.Fatalf("outgoing socket closed %d times after serving ended, want 1", upstream.closes.Load())
			}
		})
	}
}

func TestListenPacketReportsIPPeerAsIPPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proxy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := permuteproxy.NetworkFuncs{ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) { return proxy, nil }}
	srv, err := permuteproxy.Engine{Base: base, Upstream: system}.Server(chain(t, "ss+udp://aes-256-gcm:p@"+proxy.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run(ctx)
	defer srv.Close()
	inner, err := permuteproxy.Engine{Base: system}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "udp", Address: proxy.LocalAddr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := NewClient(permuteproxy.Options{KeyUsername: "aes-256-gcm", KeyPassword: "p"})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := funcs.ListenPacket(ctx, inner, system, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	peer := echo(t)
	if _, err := pc.WriteTo([]byte("ping"), peer); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, from, err := pc.ReadFrom(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if from.String() != peer.String() {
		t.Fatalf("ReadFrom source = %v (%T), want %v as ip:port", from, from, peer)
	}
}

func TestSchemesAcceptOnlyTheCredentialOptions(t *testing.T) {
	want := permuteproxy.Options{"encrypto": "aes-256-gcm", "password": "p"}
	for _, scheme := range []string{"ss", "shadowsocks"} {
		c, err := permuteproxy.ParseURI(scheme + "://aes-256-gcm:p@127.0.0.1:1")
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if got := c.Layers[0].Options; !maps.Equal(got, want) {
			t.Fatalf("%s userinfo filled %v, want %v", scheme, got, want)
		}
		if _, err := permuteproxy.ParseURI(scheme + "://127.0.0.1:1?cipher=aes-256-gcm"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Fatalf("%s took an option other than encrypto and password: %v", scheme, err)
		}
	}
}
