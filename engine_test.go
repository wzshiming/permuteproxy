package permuteproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func parse(t *testing.T, uri string) Chain {
	t.Helper()
	c, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func assertCalls(t *testing.T, want ...string) {
	t.Helper()
	if diff := cmp.Diff(want, calls); diff != "" {
		t.Fatalf("calls mismatch (-want +got):\n%s", diff)
	}
	calls = nil
}

// assertRun runs srv to its end and checks the calls made meanwhile, in any order since its planes are served in parallel.
func assertRun(t *testing.T, srv Server, want ...string) {
	t.Helper()
	calls = nil
	if err := srv.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, calls, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Fatalf("Run calls mismatch (-want +got):\n%s", diff)
	}
	calls = nil
}

func TestEngineTransport(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	c := parse(t, "test-snappy+test-tls://127.0.0.1:1?tls_skip_verify=true")
	tr, err := e.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-tls.new", "test-snappy.new")
	if tr.Planes() != Stream {
		t.Fatalf("Planes() = %v", tr.Planes())
	}
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.dial tcp 127.0.0.1:1", "test-tls.client", "test-snappy.client", "base.listen tcp 127.0.0.1:1", "test-tls.listener", "test-snappy.listener")
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
	if diff := cmp.Diff(parse(t, "test-snappy+test-tls://127.0.0.1:1?tls_skip_verify=true"), c); diff != "" {
		t.Fatalf("chain mutated by build (-want +got):\n%s", diff)
	}
	if _, err := e.Transport(c); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-tls.new", "test-snappy.new")

	quic, err := e.Transport(parse(t, "test-quic://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if quic.Planes() != Stream {
		t.Fatalf("quic Planes() = %v", quic.Planes())
	}
	if _, err := quic.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-quic.new", "base.listenpacket udp 127.0.0.1:1", "test-quic.packetlistener")
}

func TestEngineClientServer(t *testing.T) {
	calls = nil
	ctx := context.Background()
	base, upstream := &fakeNet{name: "base"}, &fakeNet{name: "upstream"}
	e := Engine{Base: base, Upstream: upstream}
	tests := []struct {
		uri    string
		dial   string
		client string
		serve  []string
	}{
		{"test-ss://127.0.0.1:1", "tcp", "test-ss.dial stream|packet tcp x:1", []string{"base.listen tcp 127.0.0.1:1", "base.listenpacket udp 127.0.0.1:1", "test-ss.serve upstream=upstream", "test-ss.servepacket upstream=upstream"}},
		{"test-ss+test-tls://127.0.0.1:1", "tcp", "test-ss.dial stream tcp x:1", []string{"base.listen tcp 127.0.0.1:1", "test-tls.listener", "test-ss.serve upstream=upstream"}},
		{"test-ss+udp://127.0.0.1:1", "udp", "test-ss.listenpacket packet local=base udp :0", []string{"base.listenpacket udp 127.0.0.1:1", "test-ss.servepacket upstream=upstream"}},
		{"test-socks5+test-quic://127.0.0.1:1", "tcp", "test-socks5.dial stream tcp x:1", []string{"base.listenpacket udp 127.0.0.1:1", "test-quic.packetlistener", "test-socks5.serve upstream=upstream"}},
		{"test-http://u:p@127.0.0.1:1", "tcp", "test-http.dial stream tcp x:1", []string{"base.listen tcp 127.0.0.1:1", "test-http.serve upstream=upstream"}},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			c := parse(t, tt.uri)
			n, err := e.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := n.DialContext(ctx, tt.dial, "x:1"); err != nil {
				t.Fatal(err)
			}
			srv, err := e.Server(c)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			if len(c.Layers) > 1 {
				want = append(want, c.Layers[1].Scheme+".new")
			}
			want = append(want, c.Layers[0].Scheme+".new", tt.client)
			if len(c.Layers) > 1 {
				want = append(want, c.Layers[1].Scheme+".new")
			}
			want = append(want, c.Layers[0].Scheme+".newserver")
			assertCalls(t, want...)
			assertRun(t, srv, tt.serve...)
			if diff := cmp.Diff(parse(t, tt.uri), c); diff != "" {
				t.Fatalf("chain mutated by build (-want +got):\n%s", diff)
			}
		})
	}
	srv, err := (Engine{}).Server(parse(t, "test-ss://127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-ss.newserver")
	assertRun(t, srv, "test-ss.serve upstream=default", "test-ss.servepacket upstream=default")
}

func TestEngineRejects(t *testing.T) {
	calls = nil
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		name string
		run  func(Chain) error
		uri  string
		want error
	}{
		{"transport of proxy", func(c Chain) error { _, err := e.Transport(c); return err }, "test-http://127.0.0.1:1", ErrInvalidChain},
		{"client of adapter", func(c Chain) error { _, err := e.Client(c); return err }, "test-tls://127.0.0.1:1", ErrInvalidChain},
		{"server of adapter", func(c Chain) error { _, err := e.Server(c); return err }, "test-tls://127.0.0.1:1", ErrInvalidChain},
		{"server of raw endpoint", func(c Chain) error { _, err := e.Server(c); return err }, "tcp://127.0.0.1:1", ErrInvalidChain},
		{"client without constructor", func(c Chain) error { _, err := e.Client(c); return err }, "test-any+test-tls://127.0.0.1:1", ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(parse(t, tt.uri))
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			assertCalls(t)
		})
	}
	for _, c := range []Chain{mk("tcp", "test-quic"), mk("udp", "test-tls"), mk("udp", "test-ss", "test-tls")} {
		if _, err := e.Transport(c); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("Transport(%+v) = %v, want ErrInvalidChain", c, err)
		}
		if _, err := e.Client(c); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("Client(%+v) = %v, want ErrInvalidChain", c, err)
		}
		assertCalls(t)
	}
}

func TestFuncsUnsupported(t *testing.T) {
	ctx := context.Background()
	var n Network = NetworkFuncs{}
	var tr Transport = TransportFuncs{Plane: Stream}
	for name, err := range map[string]error{
		"net dial":         func() error { _, err := n.DialContext(ctx, "tcp", "x"); return err }(),
		"net listen":       func() error { _, err := n.Listen(ctx, "tcp", "x"); return err }(),
		"net listenpacket": func() error { _, err := n.ListenPacket(ctx, "udp", "x"); return err }(),
		"transport dial":   func() error { _, err := tr.Dial(ctx, Stream); return err }(),
		"transport listen": func() error { _, err := tr.Listen(ctx); return err }(),
	} {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want ErrUnsupported", name, err)
		}
	}
}

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

func TestEngineBaseSelection(t *testing.T) {
	calls = nil
	ctx := context.Background()
	c := Chain{Endpoint: Endpoint{Network: "fakenet", Address: "x"}}
	tr, err := Engine{}.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "impl.dial fakenet x")
	tr, err = Engine{Base: &fakeNet{name: "base"}}.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.dial fakenet x")
	tr, err = Engine{}.Transport(Chain{Endpoint: Endpoint{Network: "tcp", Address: "127.0.0.1:0"}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tr.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if ln.Addr().Network() != "tcp" {
		t.Fatalf("zero Engine listened on %v, want the system tcp network", ln.Addr())
	}
	assertCalls(t)
}

func TestEngineNilBaseResolvesEachCallByName(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{}.Transport(Chain{Endpoint: Endpoint{Network: "test-cmd", Address: "nc host 1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Dial(ctx, Stream); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial on a network without implementation = %v, want ErrUnsupported", err)
	}
	if _, err := tr.Listen(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Listen on a network without implementation = %v, want ErrUnsupported", err)
	}
	// The client binds its own udp end by that name, not through the endpoint network's implementation.
	n, err := Engine{}.Client(mk("fakenet", "test-peer"))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := n.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-peer.listenpacket udp4 127.0.0.1:0")
	defer pc.Close()
	if pc.LocalAddr().Network() != "udp" {
		t.Fatalf("udp4 socket bound at %v, want the system udp network", pc.LocalAddr())
	}
}

func TestEngineNilUpstreamResolvesEachCallByName(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		network string
		calls   []string
		err     error
	}{
		{"fakenet", []string{"impl.listen fakenet 127.0.0.1:0"}, nil},
		{"tcp4", nil, nil},
		{"test-cmd", nil, ErrUnsupported},
		{"bogus", nil, ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			srv, err := e.Server(Chain{Layers: []Layer{{Scheme: "test-relay", Options: Options{"relay": tt.network}}}, Endpoint: Endpoint{Network: "tcp", Address: "127.0.0.1:1"}})
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			if err := srv.Run(context.Background()); !errors.Is(err, tt.err) {
				t.Fatalf("listen %s through the nil Upstream = %v, want %v", tt.network, err, tt.err)
			}
			assertCalls(t, append([]string{"base.listen tcp 127.0.0.1:1"}, tt.calls...)...)
		})
	}
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

// datagramPeer listens on an ephemeral address of network, a temp path for unixgram.
func datagramPeer(t *testing.T, network string) net.PacketConn {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "unixgram" {
		if runtime.GOOS == "windows" {
			t.Skip("unixgram needs a POSIX system")
		}
		address = filepath.Join(t.TempDir(), "p")
	}
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

// exchange proves conn is an unconnected datagram socket bound to target: Write reaches target,
// WriteTo reaches a second peer and that peer's reply arrives through ReadFrom with its address.
func exchange(t *testing.T, conn net.Conn, target net.PacketConn) {
	t.Helper()
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("conn is not a net.PacketConn")
	}
	if conn.RemoteAddr().String() != target.LocalAddr().String() {
		t.Fatalf("RemoteAddr() = %v, want %v", conn.RemoteAddr(), target.LocalAddr())
	}
	other := datagramPeer(t, target.LocalAddr().Network())
	buf := make([]byte, 16)
	for _, step := range []struct {
		to   net.Addr
		peer net.PacketConn
	}{{nil, target}, {other.LocalAddr(), other}} {
		var err error
		if step.to == nil {
			_, err = conn.Write([]byte("ping"))
		} else {
			_, err = pc.WriteTo([]byte("ping"), step.to)
		}
		if err != nil {
			t.Fatal(err)
		}
		n, from, err := step.peer.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("peer read %q, %v", buf[:n], err)
		}
		if _, err := step.peer.WriteTo([]byte("pong"), from); err != nil {
			t.Fatal(err)
		}
		n, from, err = pc.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "pong" || from.String() != step.peer.LocalAddr().String() {
			t.Fatalf("ReadFrom = %q from %v, %v; want \"pong\" from %v", buf[:n], from, err, step.peer.LocalAddr())
		}
	}
}

// closedPacket closes conn and checks a unixgram conn's private socket directory is gone.
func closedPacket(t *testing.T, conn net.Conn) {
	t.Helper()
	local := conn.LocalAddr()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if local.Network() != "unixgram" {
		return
	}
	if _, err := os.Stat(filepath.Dir(local.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private directory of %v survived Close: %v", local, err)
	}
}

func TestNativeDialPacket(t *testing.T) {
	ctx := context.Background()
	for _, network := range []string{"udp", "unixgram"} {
		t.Run(network, func(t *testing.T) {
			target := datagramPeer(t, network)
			tr, err := Engine{}.Transport(Chain{Endpoint: Endpoint{Network: network, Address: target.LocalAddr().String()}})
			if err != nil {
				t.Fatal(err)
			}
			dialed, err := tr.Dial(ctx, Packet)
			if err != nil {
				t.Fatal(err)
			}
			exchange(t, dialed, target)
			closedPacket(t, dialed)
			direct, err := native.DialContext(ctx, network, target.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			exchange(t, direct, target)
			closedPacket(t, direct)
		})
	}
}

func TestNativeDialFamilies(t *testing.T) {
	ctx := context.Background()
	target := datagramPeer(t, "udp")
	conn, err := native.DialContext(ctx, "udp4", target.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, conn, target)
	closedPacket(t, conn)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if conn, err = native.DialContext(ctx, "tcp4", ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	var unknown net.UnknownNetworkError
	if _, err := native.DialContext(ctx, "bogus", "x:1"); !errors.As(err, &unknown) {
		t.Fatalf("dial bogus = %v, want net.Dialer's unknown network error", err)
	}
}

func TestEngineRestrictsTransport(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{Base: &fakeNet{name: "base"}}.Transport(parse(t, "wide://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "wide.adapt stream")
	if tr.Planes() != Stream {
		t.Fatalf("Planes() = %v, want the declared stream", tr.Planes())
	}
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "wide.dial stream", "wide.listen")
}

func netOp(ctx context.Context, n Network, op string) error {
	kind, network, _ := strings.Cut(op, " ")
	var err error
	switch kind {
	case "dial":
		_, err = n.DialContext(ctx, network, "x:1")
	case "listen":
		_, err = n.Listen(ctx, network, "x:1")
	case "listenpacket":
		_, err = n.ListenPacket(ctx, network, "x:1")
	}
	return err
}

func TestEngineRestrictsClient(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	tests := []struct {
		uri     string
		allowed []string
		refused []string
	}{
		{
			"test-legacy+tcp://127.0.0.1:1",
			[]string{"dial tcp", "dial tcp4", "dial unix", "dial fakenet", "listen tcp6"},
			[]string{"dial udp", "dial unixgram", "dial bogus", "dial ", "listen udp", "listenpacket tcp", "listenpacket udp"},
		},
		{
			"test-legacy+udp://127.0.0.1:1",
			[]string{"dial udp", "dial udp6", "dial unixgram", "listenpacket udp4"},
			[]string{"dial tcp", "dial bogus", "listen tcp", "listen udp", "listenpacket tcp"},
		},
		{
			"test-legacy://127.0.0.1:1",
			[]string{"dial tcp", "dial udp", "listen unix", "listenpacket unixgram"},
			[]string{"dial bogus", "listen udp", "listenpacket tcp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			n, err := e.Client(parse(t, tt.uri))
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			for _, op := range tt.refused {
				if err := netOp(ctx, n, op); !errors.Is(err, ErrUnsupported) {
					t.Fatalf("%q = %v, want ErrUnsupported", op, err)
				}
				assertCalls(t)
			}
			for _, op := range tt.allowed {
				if err := netOp(ctx, n, op); err != nil {
					t.Fatalf("%q = %v", op, err)
				}
				assertCalls(t, "base."+op+" x:1")
			}
		})
	}
}

func TestEngineRejectsNilResults(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	for name, err := range map[string]error{
		"adapter":             func() error { _, err := e.Transport(parse(t, "niladapter://x:1")); return err }(),
		"client":              func() error { _, err := e.Client(parse(t, "nilproxy://x:1")); return err }(),
		"server":              func() error { _, err := e.Server(parse(t, "nilproxy://x:1")); return err }(),
		"Adapt-style adapter": func() error { _, err := e.Transport(parse(t, "test-nil-adapt://x:1")); return err }(),
		"Client-style client": func() error { _, err := e.Client(parse(t, "test-nil-legacy://x:1")); return err }(),
		"Server-style server": func() error { _, err := e.Server(parse(t, "test-nil-legacy://x:1")); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("%s: got %v, want an error naming the nil result", name, err)
		}
	}
}

func TestEngineReleasesFailedBuild(t *testing.T) {
	calls = nil
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}}
	transport := func(c Chain) error { _, err := e.Transport(c); return err }
	client := func(c Chain) error { _, err := e.Client(c); return err }
	server := func(c Chain) error { _, err := e.Server(c); return err }
	tests := []struct {
		name  string
		build func(Chain) error
		chain Chain
		want  []string
	}{
		{"failing NewAdapter", transport, mk("tcp", "test-broken", "test-counted"), []string{"test-counted.close"}},
		{"nil Adapt", transport, mk("tcp", "test-nil-adapt", "test-counted"), []string{"test-counted.close"}},
		{"rejected AdapterFuncs", transport, mk("tcp", "test-reject-adapter", "test-counted"), []string{"test-reject-adapter.close", "test-counted.close"}},
		{"failing layer over two", transport, mk("tcp", "test-tls", "test-broken", "test-counted", "test-counted"), []string{"test-counted.close", "test-counted.close"}},
		{"failing NewClient", client, mk("tcp", "test-client-broken", "test-counted"), []string{"test-counted.close"}},
		{"nil Client", client, mk("tcp", "test-nil-legacy", "test-counted"), []string{"test-counted.close"}},
		{"rejected ClientFuncs", client, mk("tcp", "test-reject-client", "test-counted"), []string{"test-reject-client.close", "test-counted.close"}},
		{"rejected ClientFuncs without ListenPacket", client, mk("tcp", "test-reject-client-packet", "test-counted"), []string{"test-reject-client-packet.close", "test-counted.close"}},
		{"failing NewServer", server, mk("tcp", "test-server-broken", "test-counted"), []string{"test-counted.close"}},
		{"nil Server", server, mk("tcp", "test-nil-legacy", "test-counted"), []string{"test-counted.close"}},
		{"rejected ServerFuncs", server, mk("tcp", "test-reject-server", "test-counted"), []string{"test-reject-server.close", "test-counted.close"}},
		{"rejected ServerFuncs without ServePacket", server, mk("tcp", "test-reject-server-packet", "test-counted"), []string{"test-reject-server-packet.close", "test-counted.close"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = nil
			if err := tt.build(tt.chain); err == nil {
				t.Fatal("build succeeded, want its constructor's failure")
			}
			assertCalls(t, tt.want...)
		})
	}
}

func TestEngineBorrowsUpstream(t *testing.T) {
	var got Network
	name := fresh("borrowing")
	RegisterLayer(name, Spec{
		Kind:     KindProxy,
		Requires: Stream,
		Provides: Stream,
		NewServer: func(Options) (*ServerFuncs, error) {
			return &ServerFuncs{Serve: func(_ context.Context, _ net.Listener, upstream Network) error {
				got = upstream
				return nil
			}}, nil
		},
	})
	upstream := &closableNet{fakeNet{name: "upstream"}}
	srv, err := (Engine{Base: &fakeNet{name: "base"}, Upstream: upstream}).Server(parse(t, name+"://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(io.Closer); ok {
		t.Fatal("server received a closable upstream")
	}
	if b, ok := got.(borrowed); !ok || b.Network != Network(upstream) {
		t.Fatalf("server upstream = %#v, want the injected network borrowed", got)
	}
}

func TestViewsForwardLossy(t *testing.T) {
	lossy := &lossyNet{fakeNet{name: "lossy"}, []string{"udp"}}
	for name, view := range map[string]Network{
		"borrowed":   borrowed{lossy},
		"restricted": restricted{network: lossy, plane: Stream | Packet},
	} {
		l, ok := view.(LossyNetwork)
		if !ok {
			t.Fatalf("%s view is not a LossyNetwork", name)
		}
		if !l.Lossy("udp") || l.Lossy("unixgram") {
			t.Fatalf("%s view: Lossy(udp) = %v, Lossy(unixgram) = %v; want what its network reports", name, l.Lossy("udp"), l.Lossy("unixgram"))
		}
	}
	for name, view := range map[string]Network{
		"borrowed":   borrowed{&fakeNet{name: "plain"}},
		"restricted": restricted{network: &fakeNet{name: "plain"}, plane: Stream | Packet},
	} {
		if l, ok := view.(LossyNetwork); !ok || l.Lossy("udp") {
			t.Fatalf("%s view of a network without Lossy reports udp lossy", name)
		}
	}
}

func TestLossyCarrierRefusesPacketToLayers(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	for _, scheme := range []string{"test-dtls", "test-quic"} {
		tr, err := e.Transport(mk("udp", scheme))
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		_, dialErr := tr.Dial(ctx, tr.Planes())
		var listenErr error
		if tr.Planes() == Stream {
			_, listenErr = tr.Listen(ctx)
		} else {
			_, listenErr = tr.ListenPacket(ctx)
		}
		if !errors.Is(dialErr, ErrUnsupported) || !errors.Is(listenErr, ErrUnsupported) {
			t.Fatalf("%s over lossy udp: dial = %v, listen = %v; want ErrUnsupported for both", scheme, dialErr, listenErr)
		}
		assertCalls(t)
	}
	tr, err := e.Transport(mk("", "test-keep"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) through test-keep over lossy udp = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() through test-keep over lossy udp = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.dial tcp 127.0.0.1:1", "test-keep.client", "base.listen tcp 127.0.0.1:1", "test-keep.listener")
}

func TestBuiltPlanesFollowALossyCarrier(t *testing.T) {
	ctx := context.Background()
	e := Engine{Base: &lossyNet{fakeNet{name: "base"}, []string{"udp"}}}
	t.Run("transport", func(t *testing.T) {
		for _, tt := range []struct {
			chain  Chain
			planes Plane
		}{
			{mk("", "test-keep"), Stream},
			{mk("udp", "test-quic"), 0}, // test-quic's carrier lost all it requires
		} {
			tr, err := e.Transport(tt.chain)
			if err != nil {
				t.Fatal(err)
			}
			if tr.Planes() != tt.planes {
				t.Fatalf("Planes() of %+v above a carrier whose udp is lossy = %v, want %v", tt.chain.Layers, tr.Planes(), tt.planes)
			}
		}
	})
	t.Run("client", func(t *testing.T) {
		n, err := e.Client(mk("", "test-legacy", "test-keep"))
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		if err := netOp(ctx, n, "dial udp"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("dial udp above a carrier whose udp is lossy = %v, want ErrUnsupported", err)
		}
		assertCalls(t)
	})
	t.Run("server", func(t *testing.T) {
		srv, err := e.Server(mk("", "test-ss", "test-keep"))
		if err != nil {
			t.Fatal(err)
		}
		assertRun(t, srv, "base.listen tcp 127.0.0.1:1", "test-keep.listener", "test-ss.serve upstream=default")
	})
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

func TestEngineNilBaseReportsRegisteredLossy(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{}.Transport(mk("test-lossy-net", "test-dtls"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() over a registered lossy implementation = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
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

func TestUpstreamNeverCheckedForLossy(t *testing.T) {
	upstream := &lossyNet{fakeNet{name: "upstream"}, []string{"udp"}}
	srv, err := Engine{Base: &fakeNet{name: "base"}, Upstream: upstream}.Server(Chain{Layers: []Layer{{Scheme: "test-relay", Options: Options{"relay": "udp"}}}, Endpoint: Endpoint{Network: "tcp", Address: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := srv.Run(context.Background()); err != nil {
		t.Fatalf("binding lossy udp through Upstream = %v, want it unchecked", err)
	}
	assertCalls(t, "base.listen tcp 127.0.0.1:1", "upstream.listenpacket udp 127.0.0.1:0")
}

func TestEngineForwardsClose(t *testing.T) {
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}}
	tests := []struct {
		uri   string
		proxy bool
		want  []string
	}{
		{"closable+test-tls://127.0.0.1:1", false, []string{"closable.close"}},
		{"test-tls://127.0.0.1:1", false, nil},
		{"closableproxy://127.0.0.1:1", true, []string{"closableproxy.close"}},
		{"test-http://127.0.0.1:1", true, nil},
		{"test-legacy://127.0.0.1:1", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			var got any
			var err error
			if tt.proxy {
				got, err = e.Client(parse(t, tt.uri))
			} else {
				got, err = e.Transport(parse(t, tt.uri))
			}
			if err != nil {
				t.Fatal(err)
			}
			calls = nil
			c, ok := got.(io.Closer)
			if !ok {
				t.Fatal("result has no Close")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			assertCalls(t, tt.want...)
		})
	}
}
