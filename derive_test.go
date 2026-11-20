package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// relay is the carrier a deriving proxy dials: its far end answers each read with the command dialed and what it read, and hangs up on "eof".
type relay struct {
	net.Conn
	command string
	closed  chan struct{}
	once    sync.Once
}

func newRelay(command string) *relay {
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		buf := make([]byte, 64)
		for {
			n, err := far.Read(buf)
			if err != nil || string(buf[:n]) == "eof" {
				return
			}
			if _, err := fmt.Fprintf(far, "%s|%s", command, buf[:n]); err != nil {
				return
			}
		}
	}()
	return &relay{Conn: near, command: command, closed: make(chan struct{})}
}

func dialRelay(command string) net.Conn {
	return newRelay(command)
}

// Close records the hang-up once.
func (r *relay) Close() error {
	r.once.Do(func() {
		record("relay.close %s", r.command)
		close(r.closed)
	})
	return r.Conn.Close()
}

// derivingProxy is a Stream proxy listing networks and deriving derive without a ListenPacket; its Dial records and returns dial's conn.
func derivingProxy(name string, provides, preserves Plane, networks []string, derive map[string]string, dial func(string) net.Conn) Spec {
	return Spec{
		Kind:      KindProxy,
		Requires:  Stream,
		Provides:  provides,
		Preserves: preserves,
		Networks:  networks,
		NewClient: func(Options) (*ClientFuncs, error) {
			return &ClientFuncs{
				Dial: func(_ context.Context, inner Transport, network, address string) (net.Conn, error) {
					record("%s.dial %v %s %s", name, inner.Planes(), network, address)
					return dial(address), nil
				},
				Derive: derive,
				Close:  func() error { record("%s.close", name); return nil },
			}, nil
		},
	}
}

// relayNetworks are what a deriving proxy lists; relayed derives udp through dgram and unix through test-held from its cmd network.
var (
	relayNetworks = []string{"tcp", "cmd"}
	relayed       = map[string]string{"udp": "dgram+cmd:relay %h %p", "unix": "test-held+cmd:relay -U %h"}
)

// underived are Stream proxies a client build refuses for what they derive.
var underived = map[string]struct {
	networks []string
	derive   map[string]string
}{
	"test-derive-variant":       {relayNetworks, map[string]string{"udp4": "dgram+cmd:relay %h %p"}},
	"test-derive-unknown":       {relayNetworks, map[string]string{"bogus": "cmd:relay %a"}},
	"test-derive-nonbase":       {relayNetworks, map[string]string{"test-cmd": "cmd:relay %a"}},
	"test-derive-listed":        {[]string{"tcp", "cmd", "udp"}, map[string]string{"udp": "dgram+cmd:relay %h %p"}},
	"test-derive-unparsable":    {relayNetworks, map[string]string{"udp": "relay %h %p"}},
	"test-derive-unknown-layer": {relayNetworks, map[string]string{"udp": "bogus+dgram+cmd:relay %h %p"}},
	"test-derive-proxy-layer":   {relayNetworks, map[string]string{"udp": "test-http+cmd:relay %h %p"}},
	"test-derive-authority":     {relayNetworks, map[string]string{"udp": "dgram+cmd://relay %h %p"}},
	"test-derive-expression":    {relayNetworks, map[string]string{"udp": "test-nc-udp://%h:%p"}},
	"test-derive-unmet":         {relayNetworks, map[string]string{"udp": "test-dtls+cmd:relay %h %p"}},
	"test-derive-opaque-host":   {relayNetworks, map[string]string{"udp": "dgram+cmd:relay %a"}},
	"test-derive-path-port":     {relayNetworks, map[string]string{"unix": "cmd:relay -U %h %p"}},
	"test-derive-placeholder":   {relayNetworks, map[string]string{"udp": "dgram+cmd:relay %h %x"}},
	"test-derive-unlisted":      {relayNetworks, map[string]string{"udp": "dgram+test-cmd:relay %h %p"}},
	"test-derive-stream-udp":    {relayNetworks, map[string]string{"udp": "cmd:relay %h %p"}},
	"test-derive-packet-unix":   {relayNetworks, map[string]string{"unix": "dgram+cmd:relay -U %h"}},
}

func init() {
	RegisterLayer("test-held", declared(Stream, Stream, &AdapterFuncs{
		Stream: &Link{Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
			record("test-held.client")
			return carrier, nil
		}},
		Close: func() error { record("test-held.close"); return nil },
	}, nil))
	unixgram, unix := map[string]string{"unixgram": "dgram+cmd:relay -U %h"}, map[string]string{"unix": "cmd:relay -U %h"}
	RegisterLayer("test-derive", derivingProxy("test-derive", Stream|Packet, 0, relayNetworks, relayed, dialRelay))
	RegisterLayer("test-derive-kept", derivingProxy("test-derive-kept", 0, Stream|Packet, relayNetworks, unixgram, dialRelay))
	RegisterLayer("test-derive-listed-udp", derivingProxy("test-derive-listed-udp", Stream|Packet, 0, []string{"tcp", "cmd", "udp"}, unixgram, dialRelay))
	RegisterLayer("test-derive-unix", derivingProxy("test-derive-unix", Stream|Packet, 0, relayNetworks, unix, dialRelay))
	RegisterLayer("test-derive-kept-unix", derivingProxy("test-derive-kept-unix", 0, Stream|Packet, relayNetworks, unix, dialRelay))
	// test-uot keeps datagram boundaries over tcp, where dgram over cmd loses them.
	uot := map[string]string{"udp": "test-uot+tcp://%h:%p"}
	RegisterLayer("test-derive-uot", derivingProxy("test-derive-uot", Stream|Packet, 0, relayNetworks, uot, dialRelay))
	lossyUot := derivingProxy("test-lossy-derive-uot", Stream|Packet, 0, relayNetworks, uot, dialRelay)
	lossyUot.Lossy = Packet
	RegisterLayer("test-lossy-derive-uot", lossyUot)
	for name, d := range underived {
		RegisterLayer(name, derivingProxy(name, Stream, 0, d.networks, d.derive, dialRelay))
	}
}

// derivingClient builds the client of c over a fake base and forgets the calls the build made.
func derivingClient(t *testing.T, c Chain) Network {
	t.Helper()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeIf(n) })
	calls = nil
	return n
}

// echoes writes msg to conn and expects want back in one read.
func echoes(t *testing.T, conn net.Conn, msg, want string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != want {
		t.Fatalf("Read = %q, %v; want %q", buf[:n], err, want)
	}
}

func TestClientRefusesDerivations(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	for name := range underived {
		t.Run(name, func(t *testing.T) {
			calls = nil
			_, err := e.Client(mk("", name))
			if !errors.Is(err, ErrInvalidChain) || strings.Count(err.Error(), ErrInvalidChain.Error()) != 1 {
				t.Fatalf("Client() = %v, want it marked ErrInvalidChain once", err)
			}
			assertCalls(t, name+".close")
		})
	}
}

func TestClientCoversPacketByDerivedDatagrams(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	for _, scheme := range []string{"test-derive", "test-derive-kept"} {
		n, err := e.Client(mk("", scheme))
		if err != nil {
			t.Fatalf("Client(%s) = %v, want Packet covered by its derived datagram network", scheme, err)
		}
		closeIf(n)
	}
	calls = nil
	for _, scheme := range []string{"test-derive-unix", "test-derive-kept-unix"} {
		if _, err := e.Client(mk("", scheme)); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("Client(%s) = %v, want ErrInvalidChain since it derives no datagram network", scheme, err)
		}
		assertCalls(t, scheme+".close")
	}
}

func TestClientAdmitsDerivedNetworks(t *testing.T) {
	ctx := context.Background()
	n := derivingClient(t, mk("", "test-derive"))
	for _, network := range []string{"udp", "udp4", "udp6"} {
		conn, err := n.DialContext(ctx, network, "peer.invalid:1")
		if err != nil {
			t.Fatalf("dial %s = %v, want it admitted as derived", network, err)
		}
		conn.Close()
		pc, err := n.ListenPacket(ctx, network, ":0")
		if err != nil {
			t.Fatalf("listen packet %s = %v, want it admitted as derived", network, err)
		}
		pc.Close()
	}
	assertCalls(t)
	for name, op := range map[string]func() error{
		"dial unixgram":          func() error { _, err := n.DialContext(ctx, "unixgram", "/tmp/x"); return err },
		"listen packet unixgram": func() error { _, err := n.ListenPacket(ctx, "unixgram", ":0"); return err },
		"listen packet unix":     func() error { _, err := n.ListenPacket(ctx, "unix", ":0"); return err },
		"listen udp":             func() error { _, err := n.Listen(ctx, "udp", ":0"); return err },
		"listen unix":            func() error { _, err := n.Listen(ctx, "unix", "/tmp/x"); return err },
	} {
		if err := op(); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want ErrUnsupported", name, err)
		}
	}
	assertCalls(t)
	// Over test-tls, test-derive-kept has no datagrams to preserve, so what it derives on that plane stays refused.
	kept := derivingClient(t, mk("", "test-derive-kept", "test-tls"))
	if _, err := kept.DialContext(ctx, "unixgram", "/tmp/x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dial unixgram outside the layer's planes = %v, want ErrUnsupported", err)
	}
	if _, err := kept.ListenPacket(ctx, "unixgram", ":0"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("listen packet unixgram outside the layer's planes = %v, want ErrUnsupported", err)
	}
	conn, err := derivingClient(t, mk("", "test-derive-kept")).DialContext(ctx, "unixgram", "/tmp/x")
	if err != nil {
		t.Fatalf("dial unixgram within the layer's planes = %v", err)
	}
	conn.Close()
	assertCalls(t)
}

func TestClientWithoutListenPacketRefusesListedDatagrams(t *testing.T) {
	ctx := context.Background()
	n := derivingClient(t, mk("", "test-derive-listed-udp"))
	if _, err := n.DialContext(ctx, "udp", "127.0.0.1:1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dial udp without ListenPacket = %v, want ErrUnsupported", err)
	}
	if _, err := n.ListenPacket(ctx, "udp", ":0"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("listen packet udp without ListenPacket = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
}

func TestDerivedStreamDialsThroughTheClientItself(t *testing.T) {
	ctx := context.Background()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("tcp", "test-derive", "closable"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	conn, err := n.DialContext(ctx, "unix", "/tmp/a b.sock")
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-derive.dial stream cmd relay -U '/tmp/a b.sock'", "test-held.client")
	echoes(t, conn, "hi", "relay -U '/tmp/a b.sock'|hi")
	// The conn releases what the expression built over the client, never the client.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "relay.close relay -U '/tmp/a b.sock'", "test-held.close")
	open, err := n.DialContext(ctx, "unix", "/tmp/open.sock")
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := n.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-derive.close", "closable.close")
	echoes(t, open, "still", "relay -U /tmp/open.sock|still")
	open.Close()
	assertCalls(t, "relay.close relay -U /tmp/open.sock", "test-held.close")
}

func TestFailedDerivedDialReleasesWhatItBuilt(t *testing.T) {
	calls = nil
	spec := Spec{Kind: KindProxy, Requires: Stream, Provides: Stream, Networks: relayNetworks, NewClient: func(Options) (*ClientFuncs, error) {
		return &ClientFuncs{
			Dial:   func(context.Context, Transport, string, string) (net.Conn, error) { return nil, errLink },
			Derive: map[string]string{"unix": relayed["unix"]},
		}, nil
	}}
	n, err := spec.client(TransportFuncs{Plane: Stream}, NetworkFuncs{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DialContext(context.Background(), "unix", "/tmp/x.sock"); !errors.Is(err, errLink) {
		t.Fatalf("derived dial over a failing Dial = %v, want its error", err)
	}
	assertCalls(t, "test-held.close")
}

func TestDerivedNetworksRefuseInvalidAddresses(t *testing.T) {
	ctx := context.Background()
	n := derivingClient(t, mk("", "test-derive"))
	for _, tt := range []struct{ network, address string }{
		{"udp", "peer.invalid"},
		{"udp", "-oProxyCommand=x:1"},
		{"udp", "-h:1"},
		{"udp", "[--help]:1"},
		{"udp", "a=b:1"},
		{"udp", "a,b:1"},
		{"udp6", "a;b:1"},
		{"unix", "-x.sock"},
		{"unix", "/tmp/a\nb.sock"},
	} {
		conn, err := n.DialContext(ctx, tt.network, tt.address)
		if err == nil {
			conn.Close()
		}
		if err == nil || errors.Is(err, ErrUnsupported) {
			t.Fatalf("dial %s %q = %v, want the address refused", tt.network, tt.address, err)
		}
		assertCalls(t)
	}
}

func TestDerivedListenPacketReachesEachPeer(t *testing.T) {
	ctx := context.Background()
	client := derivingClient(t, mk("", "test-derive"))
	pc, err := client.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t)
	named, numbered := netutils.NewNetAddr("udp", "a.invalid:1"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 2}
	for _, peer := range []net.Addr{named, numbered} {
		if _, err := pc.WriteTo([]byte("hi"), peer); err != nil {
			t.Fatal(err)
		}
	}
	// A name reaches the far side unresolved.
	assertCalls(t, "test-derive.dial stream cmd relay a.invalid 1", "test-derive.dial stream cmd relay 127.0.0.2 2")
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := map[string]string{}
	buf := make([]byte, 64)
	for range 2 {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		got[from.String()] = string(buf[:n])
	}
	want := map[string]string{"a.invalid:1": "relay a.invalid 1|hi", "127.0.0.2:2": "relay 127.0.0.2 2|hi"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("datagrams by peer mismatch (-want +got):\n%s", diff)
	}
	for _, peer := range []net.Addr{
		netutils.NewNetAddr("udp", "-oProxyCommand=x:1"),
		netutils.NewNetAddr("udp", "-h:1"),
		netutils.NewNetAddr("udp", "[--help]:1"),
		netutils.NewNetAddr("udp", "a=b:1"),
		netutils.NewNetAddr("udp", "a,b:1"),
		netutils.NewNetAddr("udp", "a b:1"),
		netutils.NewNetAddr("udp", "a.invalid"),
		&net.UnixAddr{Name: "/tmp/x", Net: "unixgram"},
	} {
		if _, err := pc.WriteTo([]byte("hi"), peer); err == nil {
			t.Fatalf("WriteTo(%v) succeeded, want the peer refused", peer)
		}
	}
	assertCalls(t)
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"relay.close relay 127.0.0.2 2", "relay.close relay a.invalid 1"}, calls, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Fatalf("Close calls mismatch (-want +got):\n%s", diff)
	}
	calls = nil
	if _, err := pc.WriteTo([]byte("hi"), named); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close = %v, want net.ErrClosed", err)
	}
}

func TestDerivedListenPacketBindsOnlyAnyHostAtPortZero(t *testing.T) {
	ctx := context.Background()
	n := derivingClient(t, mk("", "test-derive"))
	for _, address := range []string{":0", "0.0.0.0:0", "[::]:0"} {
		pc, err := n.ListenPacket(ctx, "udp", address)
		if err != nil {
			t.Fatalf("ListenPacket(%q) = %v", address, err)
		}
		pc.Close()
	}
	for _, address := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0", ":53", "0.0.0.0:1", "0.0.0.0", ""} {
		if _, err := n.ListenPacket(ctx, "udp", address); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("ListenPacket(%q) = %v, want ErrUnsupported", address, err)
		}
	}
	assertCalls(t)
}

func TestDerivedDialOpensSessionOnWrite(t *testing.T) {
	ctx := context.Background()
	n := derivingClient(t, mk("", "test-derive"))
	conn, err := n.DialContext(ctx, "udp", "peer.invalid:53")
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t)
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatal("derived udp conn is not a net.PacketConn")
	}
	if remote := conn.RemoteAddr(); remote.Network() != "udp" || remote.String() != "peer.invalid:53" {
		t.Fatalf("RemoteAddr() = %s %v, want the udp address carried verbatim", remote.Network(), remote)
	}
	echoes(t, conn, "ping", "relay peer.invalid 53|ping")
	echoes(t, conn, "again", "relay peer.invalid 53|again")
	assertCalls(t, "test-derive.dial stream cmd relay peer.invalid 53")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "relay.close relay peer.invalid 53")
	if _, err := conn.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}
}

func TestDerivedDialReopensEndedSession(t *testing.T) {
	calls = nil
	ctx := context.Background()
	// The relays belong to this test, so the client is assembled directly.
	relays := make(chan *relay, 2)
	spec := derivingProxy("test-derive", Stream|Packet, 0, relayNetworks, relayed, func(command string) net.Conn {
		r := newRelay(command)
		relays <- r
		return r
	})
	n, err := spec.client(TransportFuncs{Plane: Stream}, NetworkFuncs{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := n.DialContext(ctx, "udp", "peer.invalid:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoes(t, conn, "one", "relay peer.invalid 53|one")
	first := recv(t, relays, "the first dial")
	// The relay hangs up on eof, which ends the session.
	if _, err := conn.Write([]byte("eof")); err != nil {
		t.Fatal(err)
	}
	recv(t, first.closed, "the ended session's close")
	echoes(t, conn, "two", "relay peer.invalid 53|two")
	recv(t, relays, "the second dial")
	assertCalls(t, "test-derive.dial stream cmd relay peer.invalid 53", "relay.close relay peer.invalid 53", "test-derive.dial stream cmd relay peer.invalid 53")
}

func TestDerivationThroughNetworkWithoutDialIsRefused(t *testing.T) {
	ctx := context.Background()
	// A layer offering only datagrams lists cmd for its derivation alone, so nothing has it declare a Dial.
	spec := Spec{Kind: KindProxy, Requires: Stream, Provides: Packet, Networks: []string{"cmd"}, NewClient: func(Options) (*ClientFuncs, error) {
		return &ClientFuncs{Derive: map[string]string{"udp": "dgram+cmd:relay %h %p"}}, nil
	}}
	n, err := spec.client(TransportFuncs{Plane: Stream}, NetworkFuncs{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := n.DialContext(ctx, "udp", "peer.invalid:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Write through a cmd network without Dial = %v, want ErrUnsupported", err)
	}
}

func TestClientReportsDerivedLossy(t *testing.T) {
	tests := []struct {
		scheme string
		lossy  map[string]bool
	}{
		{"test-derive", map[string]bool{"udp": true, "udp6": true, "unix": false, "tcp": false, "cmd": false, "unixgram": false}},
		{"test-derive-kept", map[string]bool{"unixgram": true, "udp": false}},
		{"test-derive-uot", map[string]bool{"udp": false, "udp4": false}},
		{"test-lossy-derive-uot", map[string]bool{"udp": true, "tcp": false}},
	}
	for _, tt := range tests {
		l, ok := derivingClient(t, mk("", tt.scheme)).(LossyNetwork)
		if !ok {
			t.Fatalf("Client of %s is not a LossyNetwork", tt.scheme)
		}
		for network, want := range tt.lossy {
			if got := l.Lossy(network); got != want {
				t.Fatalf("Client of %s: Lossy(%q) = %v, want %v", tt.scheme, network, got, want)
			}
		}
	}
}

func TestDerivedLossyRefusesPacketToLayers(t *testing.T) {
	ctx := context.Background()
	tr, err := Engine{Base: derivingClient(t, mk("", "test-derive"))}.Transport(mk("udp", "test-dtls"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) over udp derived through dgram = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() over udp derived through dgram = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
	if tr, err = (Engine{Base: derivingClient(t, mk("", "test-derive-uot"))}).Transport(mk("udp", "test-dtls")); err != nil {
		t.Fatal(err)
	}
	calls = nil
	conn, err := tr.Dial(ctx, Packet)
	if err != nil {
		t.Fatalf("Dial(Packet) over udp derived with datagram boundaries = %v", err)
	}
	conn.Close()
	assertCalls(t, "test-dtls.client")
}
