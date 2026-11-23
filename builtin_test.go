package permuteproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestRootDeclaresBaseNetworks(t *testing.T) {
	want := map[string]NetworkSpec{
		"tcp":      {Plane: Stream, AddressKind: AddressHost},
		"udp":      {Plane: Packet, AddressKind: AddressHost},
		"unix":     {Plane: Stream, AddressKind: AddressPath},
		"unixgram": {Plane: Packet, AddressKind: AddressPath},
		"cmd":      {Plane: Stream, AddressKind: AddressOpaque},
	}
	if diff := cmp.Diff(want, atRootInit.networks); diff != "" {
		t.Fatalf("networks without any protocols package (-want +got):\n%s", diff)
	}
	wantCmd := Chain{Endpoint: Endpoint{Network: "cmd", Address: "nc host 1"}}
	if diff := cmp.Diff(wantCmd, atRootInit.cmd); atRootInit.cmdErr != nil || diff != "" {
		t.Fatalf("ParseURI(\"cmd:nc host 1\") without any protocols package = %v (-want +got):\n%s", atRootInit.cmdErr, diff)
	}
}

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
