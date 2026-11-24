package permuteproxy

import (
	"context"
	"errors"
	"io"
	"net"
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
		{"server without constructor", func(c Chain) error { _, err := e.Server(c); return err }, "test-peer://127.0.0.1:1", ErrUnsupported},
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

func TestEngineRejectsNilResults(t *testing.T) {
	e := Engine{Base: &fakeNet{name: "base"}}
	for name, err := range map[string]error{
		"adapter": func() error { _, err := e.Transport(parse(t, "niladapter://x:1")); return err }(),
		"client":  func() error { _, err := e.Client(parse(t, "nilproxy://x:1")); return err }(),
		"server":  func() error { _, err := e.Server(parse(t, "nilproxy://x:1")); return err }(),
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
		{"nil AdapterFuncs", transport, mk("tcp", "niladapter", "test-counted"), []string{"test-counted.close"}},
		{"rejected AdapterFuncs", transport, mk("tcp", "test-reject-adapter", "test-counted"), []string{"test-reject-adapter.close", "test-counted.close"}},
		{"failing layer over two", transport, mk("tcp", "test-tls", "test-broken", "test-counted", "test-counted"), []string{"test-counted.close", "test-counted.close"}},
		{"failing NewClient", client, mk("tcp", "test-client-broken", "test-counted"), []string{"test-counted.close"}},
		{"nil ClientFuncs", client, mk("tcp", "nilproxy", "test-counted"), []string{"test-counted.close"}},
		{"rejected ClientFuncs", client, mk("tcp", "test-reject-client", "test-counted"), []string{"test-reject-client.close", "test-counted.close"}},
		{"rejected ClientFuncs without ListenPacket", client, mk("tcp", "test-reject-client-packet", "test-counted"), []string{"test-reject-client-packet.close", "test-counted.close"}},
		{"rejected Derive", client, mk("tcp", "test-derive-quoted", "test-counted"), []string{"test-derive-quoted.close", "test-counted.close"}},
		{"failing NewServer", server, mk("tcp", "test-server-broken", "test-counted"), []string{"test-counted.close"}},
		{"nil ServerFuncs", server, mk("tcp", "nilproxy", "test-counted"), []string{"test-counted.close"}},
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
	RegisterLayer(name, LayerSpec{
		Kind:     LayerProxy,
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

func TestEngineBorrowsBaseForClient(t *testing.T) {
	var got Network
	name := fresh("borrowing-client")
	RegisterLayer(name, LayerSpec{
		Kind:     LayerProxy,
		Requires: Stream,
		Provides: Packet,
		Networks: []string{"udp"},
		NewClient: func(Options) (*ClientFuncs, error) {
			return &ClientFuncs{ListenPacket: func(_ context.Context, _ Transport, local Network, _, _ string) (net.PacketConn, error) {
				got = local
				return idlePacketConn{}, nil
			}}, nil
		},
	})
	base := &closableNet{fakeNet{name: "base"}}
	n, err := (Engine{Base: base}).Client(parse(t, name+"://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.ListenPacket(context.Background(), "udp", ":0"); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(io.Closer); ok {
		t.Fatal("client received a closable base")
	}
	if b, ok := got.(borrowed); !ok || b.Network != Network(base) {
		t.Fatalf("client local = %#v, want the injected base borrowed", got)
	}
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
		n, err := e.Client(mk("", "test-derive-kept", "test-keep"))
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

func TestEngineNilBaseReportsRegisteredLossy(t *testing.T) {
	calls = nil
	ctx := context.Background()
	tr, err := Engine{}.Transport(mk("test-lossy-net", "test-dtls"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) over a registered lossy implementation = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
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
