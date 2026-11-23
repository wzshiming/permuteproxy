package permuteproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestDgramDeclaration(t *testing.T) {
	spec, ok := lookupLayer("dgram")
	if !ok {
		t.Fatal("dgram is not registered")
	}
	if spec.Kind != LayerAdapter || spec.Requires != Stream || spec.Provides != Packet || spec.Preserves != 0 || spec.Lossy != Packet {
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
	if got := testutils.Wait(t, read, "carrier read"); got != "ping" {
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
