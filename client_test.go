package permuteproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestClientDialsStream(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-socks5", "test-quic"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-quic.new", "test-socks5.new")
	for _, network := range []string{"tcp", "tcp4", "tcp6"} {
		if _, err := n.DialContext(ctx, network, "x:1"); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, "test-socks5.dial stream "+network+" x:1")
	}
}

func TestClientAdmitsListedNetworks(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		uri     string
		allowed map[string]string
		refused []string
	}{
		{
			"test-http://127.0.0.1:1",
			map[string]string{
				"dial tcp":  "test-http.dial stream tcp x:1",
				"dial tcp4": "test-http.dial stream tcp4 x:1",
				"dial tcp6": "test-http.dial stream tcp6 x:1",
			},
			[]string{"dial unix", "dial fakenet", "dial udp", "dial udp4", "dial unixgram", "dial bogus", "dial ", "listenpacket udp", "listenpacket tcp"},
		},
		{
			"test-ss+udp://127.0.0.1:1",
			map[string]string{
				"dial udp":              "test-ss.listenpacket packet local=base udp :0",
				"dial udp4":             "test-ss.listenpacket packet local=base udp :0",
				"listenpacket udp6":     "test-ss.listenpacket packet local=base udp6 x:1",
				"listenpacket unixgram": "test-ss.listenpacket packet local=base unixgram x:1",
			},
			[]string{"dial tcp", "dial tcp6", "dial unixgram", "listenpacket tcp", "listenpacket bogus"},
		},
		{
			"test-ss://127.0.0.1:1",
			map[string]string{
				"dial tcp4":        "test-ss.dial stream|packet tcp4 x:1",
				"dial udp6":        "test-ss.listenpacket stream|packet local=base udp :0",
				"listenpacket udp": "test-ss.listenpacket stream|packet local=base udp x:1",
			},
			[]string{"dial unix", "dial fakenet", "listenpacket unix", "listenpacket tcp4", "listen tcp", "listen tcp6", "listen unix", "listen fakenet", "listen udp", "listen bogus"},
		},
		{"test-peer://127.0.0.1:1", nil, []string{"listenpacket unixgram", "dial unixgram", "dial tcp"}},
		// cmd is listed but no system network, so only its registration lets the plane gate admit it.
		{"test-derive://127.0.0.1:1", map[string]string{"dial cmd": "test-derive.dial stream cmd x:1"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			n, err := e.Client(parse(t, tt.uri))
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			for _, op := range tt.refused {
				err := netOp(ctx, n, op)
				if !errors.Is(err, ErrUnsupported) {
					t.Fatalf("%q = %v, want ErrUnsupported", op, err)
				}
				if strings.HasPrefix(op, "listen ") && err.Error() != op+": unsupported" {
					t.Fatalf("%q = %v, want %q", op, err, op+": unsupported")
				}
				assertCalls(t)
			}
			for op, want := range tt.allowed {
				if err := netOp(ctx, n, op); err != nil {
					t.Fatalf("%q = %v", op, err)
				}
				assertCalls(t, want)
			}
		})
	}
}

func TestClientListensPacketThroughLocal(t *testing.T) {
	calls = nil
	ctx := context.Background()
	base := &fakeNet{name: "base"}
	tests := []struct {
		engine Engine
		chain  Chain
		local  string
	}{
		{Engine{Base: base}, mk("fakenet", "test-socks5"), "base"},
		{Engine{}, mk("fakenet", "test-socks5"), "default"},
		{Engine{}, mk("tcp", "test-socks5"), "default"},
	}
	for _, tt := range tests {
		n, err := tt.engine.Client(tt.chain)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		if _, err := n.ListenPacket(ctx, "udp4", "x:1"); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, "test-socks5.listenpacket stream local="+tt.local+" udp4 x:1")
	}
}

func TestClientDerivesUDPDial(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-socks5"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := n.DialContext(ctx, "unixgram", "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unixgram dial = %v, want ErrUnsupported outside the udp family", err)
	}
	assertCalls(t)
	conn, err := n.DialContext(ctx, "udp6", "unresolvable.invalid:1")
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-socks5.listenpacket stream local=base udp :0")
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatal("udp conn is not a net.PacketConn")
	}
	if remote := conn.RemoteAddr(); remote.Network() != "udp" || remote.String() != "unresolvable.invalid:1" {
		t.Fatalf("RemoteAddr() = %s %v, want the udp address carried verbatim", remote.Network(), remote)
	}
}

func TestClientAsksPeerOfUDPDial(t *testing.T) {
	calls = nil
	ctx := context.Background()
	n, err := Engine{}.Client(mk("", "test-peer"))
	if err != nil {
		t.Fatal(err)
	}
	target := datagramPeer(t, "udp")
	address := target.LocalAddr().String()
	conn, err := n.DialContext(ctx, "udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-peer.peer udp4 "+address, "test-peer.listenpacket udp :0")
	exchange(t, conn, target)
	closedPacket(t, conn)
	if _, err := n.DialContext(ctx, "udp", "x"); err == nil {
		t.Fatal("udp dial to an address Peer refuses succeeded")
	}
	assertCalls(t, "test-peer.peer udp x")
}

func TestClientRejectsDeclarations(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	schemes := []string{"nilproxy", "test-client-broken"}
	for name := range uncoveredClients {
		schemes = append(schemes, name)
	}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			if _, err := e.Client(mk("", scheme)); !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Client() = %v, want ErrInvalidChain", err)
			}
			assertCalls(t)
		})
	}
	if _, err := e.Client(mk("", "test-client-broken")); !errors.Is(err, errDeclare) {
		t.Fatalf("Client() = %v, want the NewClient error kept", err)
	}
}

func TestClientReportsLossyFromLayerSpec(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		scheme string
		lossy  map[string]bool
	}{
		{"test-lossy-proxy", map[string]bool{"udp": true, "udp6": true, "unixgram": true, "tcp": false, "unix": false, "bogus": false}},
		{"test-socks5", map[string]bool{"udp": false, "unixgram": false, "tcp": false}},
	}
	for _, tt := range tests {
		n, err := e.Client(mk("", tt.scheme))
		if err != nil {
			t.Fatal(err)
		}
		l, ok := n.(LossyNetwork)
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

func TestLossyLocalRefusesClientPacket(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	n, err := e.Client(mk("", "test-socks5"))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := e.Client(mk("", "test-peer"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	// A local answering for udp answers for its families too.
	for _, op := range []string{"listenpacket udp", "dial udp", "dial udp4", "listenpacket udp4", "dial udp6", "listenpacket udp6"} {
		if err := netOp(ctx, n, op); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%q with a lossy local = %v, want ErrUnsupported", op, err)
		}
		if err := netOp(ctx, peer, op); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%q with a lossy local and a Peer = %v, want ErrUnsupported", op, err)
		}
		assertCalls(t)
	}
	for op, want := range map[string]string{
		"dial tcp":              "test-socks5.dial stream tcp x:1",
		"listenpacket unixgram": "test-socks5.listenpacket stream local=base unixgram x:1",
	} {
		if err := netOp(ctx, n, op); err != nil {
			t.Fatalf("%q = %v", op, err)
		}
		assertCalls(t, want)
	}
}

func TestClientWithoutListenPacketRefusesListedDatagrams(t *testing.T) {
	calls = nil
	ctx := context.Background()
	// The engine refuses datagrams to a proxy without Packet first, so this one is assembled directly.
	n, err := derivingProxy("test-derive", Stream, 0, []string{"tcp", "udp", "unixgram"}, nil, dialRelay).client(TransportFuncs{Plane: Stream}, NetworkFuncs{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DialContext(ctx, "udp", "127.0.0.1:1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dial udp without ListenPacket = %v, want ErrUnsupported", err)
	}
	if _, err := n.ListenPacket(ctx, "unixgram", "/tmp/x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("listen packet unixgram without ListenPacket = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
}
