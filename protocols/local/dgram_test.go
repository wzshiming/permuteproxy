package local

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestDgramDeclaration(t *testing.T) {
	if dgram.NewAdapter == nil || dgram.Requires != permuteproxy.Stream || dgram.Provides != permuteproxy.Packet || dgram.Preserves != 0 || dgram.Lossy != permuteproxy.Packet {
		t.Fatalf("dgram declares adapter %v, requires %v, provides %v, preserves %v, lossy %v", dgram.NewAdapter != nil, dgram.Requires, dgram.Provides, dgram.Preserves, dgram.Lossy)
	}
	c, err := permuteproxy.ParseURI("dgram+cmd:nc host 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := permuteproxy.ParseURI("test-datagrams+dgram+cmd:nc host 1"); !errors.Is(err, permuteproxy.ErrInvalidChain) || !strings.Contains(err.Error(), "datagram boundaries") {
		t.Fatalf("ParseURI with Packet required over dgram = %v, want ErrInvalidChain naming datagram boundaries", err)
	}
}

func TestDgramDialsStreamCarrierAsDatagrams(t *testing.T) {
	ctx := context.Background()
	near, far := net.Pipe()
	defer far.Close()
	peer := netutils.NewNetAddr("cmd", "nc host 1")
	var calls []string
	base := permuteproxy.NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
		calls = append(calls, "dial "+network+" "+address)
		return netutils.ConnWithAddr(near, nil, peer), nil
	}}
	c, err := permuteproxy.ParseURI("dgram+cmd:nc host 1")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := permuteproxy.TransportEngine{Base: base}.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Planes() != permuteproxy.Packet {
		t.Fatalf("Planes() = %v, want packet", tr.Planes())
	}
	conn, err := tr.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if want := []string{"dial cmd nc host 1"}; !slices.Equal(calls, want) {
		t.Fatalf("base calls = %q, want %q", calls, want)
	}
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
	if got := testutils.Wait(t, read, "carrier read"); got != "ping" {
		t.Fatalf("carrier read %q, want ping", got)
	}
	go far.Write([]byte("pong"))
	buf := make([]byte, 16)
	if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "pong" || from != peer {
		t.Fatalf("ReadFrom = %q from %v, %v; want pong from %v", buf[:n], from, err, peer)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("ListenPacket() = %v, want ErrUnsupported", err)
	}
	if _, err := tr.Listen(ctx); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Listen() = %v, want ErrUnsupported", err)
	}
	if len(calls) != 1 {
		t.Fatalf("base calls = %q, want only the dial", calls)
	}
}
