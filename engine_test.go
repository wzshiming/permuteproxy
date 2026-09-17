package permuteproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestEngineTransport(t *testing.T) {
	calls = nil
	ctx := context.Background()
	e := Engine{Base: &fakeNet{name: "base"}}
	c := parse(t, "snappy+tls://127.0.0.1:1?tls_skip_verify=true")
	tr, err := e.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "tls.adapt stream", "snappy.adapt stream")
	if tr.Planes() != Stream {
		t.Fatalf("Planes() = %v", tr.Planes())
	}
	if _, err := tr.Dial(ctx, Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "base.dial tcp 127.0.0.1:1", "base.listen tcp 127.0.0.1:1")
	if _, err := tr.Dial(ctx, Packet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial(Packet) = %v, want ErrUnsupported", err)
	}
	if _, err := tr.ListenPacket(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenPacket() = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
	if diff := cmp.Diff(parse(t, "snappy+tls://127.0.0.1:1?tls_skip_verify=true"), c); diff != "" {
		t.Fatalf("chain mutated by build (-want +got):\n%s", diff)
	}
	if _, err := e.Transport(c); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "tls.adapt stream", "snappy.adapt stream")

	quic, err := e.Transport(parse(t, "quic://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if quic.Planes() != Stream {
		t.Fatalf("quic Planes() = %v", quic.Planes())
	}
	if _, err := quic.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "quic.adapt packet", "base.listenpacket udp 127.0.0.1:1")
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
		server string
	}{
		{"ss://127.0.0.1:1", "tcp", "ss.client stream|packet base=base", "ss.server stream|packet upstream=upstream"},
		{"ss+tls://127.0.0.1:1", "tcp", "ss.client stream base=base", "ss.server stream upstream=upstream"},
		{"ss+udp://127.0.0.1:1", "udp", "ss.client packet base=base", "ss.server packet upstream=upstream"},
		{"socks5+quic://127.0.0.1:1", "tcp", "socks5.client stream base=base", "socks5.server stream upstream=upstream"},
		{"http://u:p@127.0.0.1:1", "tcp", "http.client stream base=base", "http.server stream upstream=upstream"},
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
			if _, err := e.Server(c); err != nil {
				t.Fatal(err)
			}
			var want []string
			if len(c.Layers) > 1 {
				want = append(want, c.Layers[1].Scheme+".adapt "+adapterCarrier(c))
			}
			want = append(want, tt.client, "base.dial "+tt.dial+" x:1")
			if len(c.Layers) > 1 {
				want = append(want, c.Layers[1].Scheme+".adapt "+adapterCarrier(c))
			}
			want = append(want, tt.server)
			assertCalls(t, want...)
			if diff := cmp.Diff(parse(t, tt.uri), c); diff != "" {
				t.Fatalf("chain mutated by build (-want +got):\n%s", diff)
			}
		})
	}
	if _, err := (Engine{}).Server(parse(t, "ss://127.0.0.1:1")); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "ss.server stream|packet upstream=native")
}

func adapterCarrier(c Chain) string {
	if c.Layers[1].Scheme == "quic" {
		return "packet"
	}
	return "stream"
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
		{"transport of proxy", func(c Chain) error { _, err := e.Transport(c); return err }, "http://127.0.0.1:1", ErrInvalidChain},
		{"client of adapter", func(c Chain) error { _, err := e.Client(c); return err }, "tls://127.0.0.1:1", ErrInvalidChain},
		{"server of adapter", func(c Chain) error { _, err := e.Server(c); return err }, "tls://127.0.0.1:1", ErrInvalidChain},
		{"server of raw endpoint", func(c Chain) error { _, err := e.Server(c); return err }, "tcp://127.0.0.1:1", ErrInvalidChain},
		{"client without constructor", func(c Chain) error { _, err := e.Client(c); return err }, "any+tls://127.0.0.1:1", ErrUnsupported},
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
	for _, c := range []Chain{mk("tcp", "quic"), mk("udp", "tls"), mk("udp", "ss", "tls")} {
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
			"http://127.0.0.1:1",
			[]string{"dial tcp", "dial tcp4", "dial unix", "dial fakenet", "listen tcp6"},
			[]string{"dial udp", "dial unixgram", "dial bogus", "dial ", "listen udp", "listenpacket tcp", "listenpacket udp"},
		},
		{
			"ss+udp://127.0.0.1:1",
			[]string{"dial udp", "dial udp6", "dial unixgram", "listenpacket udp4"},
			[]string{"dial tcp", "dial bogus", "listen tcp", "listen udp", "listenpacket tcp"},
		},
		{
			"ss://127.0.0.1:1",
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
		"adapter": func() error { _, err := e.Transport(parse(t, "niladapter://x:1")); return err }(),
		"client":  func() error { _, err := e.Client(parse(t, "nilproxy://x:1")); return err }(),
		"server":  func() error { _, err := e.Server(parse(t, "nilproxy://x:1")); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("%s: got %v, want an error naming the nil result", name, err)
		}
	}
}

func TestEngineForwardsClose(t *testing.T) {
	e := Engine{Base: &closableNet{fakeNet{name: "base"}}}
	tests := []struct {
		uri   string
		proxy bool
		want  []string
	}{
		{"closable+tls://127.0.0.1:1", false, []string{"closable.close"}},
		{"tls://127.0.0.1:1", false, nil},
		{"closableproxy://127.0.0.1:1", true, []string{"closableproxy.close"}},
		{"http://127.0.0.1:1", true, nil},
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
