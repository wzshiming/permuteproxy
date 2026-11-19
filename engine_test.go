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
		server string
	}{
		{"test-ss://127.0.0.1:1", "tcp", "test-ss.client stream|packet base=base", "test-ss.server stream|packet upstream=upstream"},
		{"test-ss+test-tls://127.0.0.1:1", "tcp", "test-ss.client stream base=base", "test-ss.server stream upstream=upstream"},
		{"test-ss+udp://127.0.0.1:1", "udp", "test-ss.client packet base=base", "test-ss.server packet upstream=upstream"},
		{"test-socks5+test-quic://127.0.0.1:1", "tcp", "test-socks5.client stream base=base", "test-socks5.server stream upstream=upstream"},
		{"test-http://u:p@127.0.0.1:1", "tcp", "test-http.client stream base=base", "test-http.server stream upstream=upstream"},
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
				want = append(want, c.Layers[1].Scheme+".new")
			}
			want = append(want, tt.client, "base.dial "+tt.dial+" x:1")
			if len(c.Layers) > 1 {
				want = append(want, c.Layers[1].Scheme+".new")
			}
			want = append(want, tt.server)
			assertCalls(t, want...)
			if diff := cmp.Diff(parse(t, tt.uri), c); diff != "" {
				t.Fatalf("chain mutated by build (-want +got):\n%s", diff)
			}
		})
	}
	if _, err := (Engine{}).Server(parse(t, "test-ss://127.0.0.1:1")); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "test-ss.server stream|packet upstream=native")
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
			"test-http://127.0.0.1:1",
			[]string{"dial tcp", "dial tcp4", "dial unix", "dial fakenet", "listen tcp6"},
			[]string{"dial udp", "dial unixgram", "dial bogus", "dial ", "listen udp", "listenpacket tcp", "listenpacket udp"},
		},
		{
			"test-ss+udp://127.0.0.1:1",
			[]string{"dial udp", "dial udp6", "dial unixgram", "listenpacket udp4"},
			[]string{"dial tcp", "dial bogus", "listen tcp", "listen udp", "listenpacket tcp"},
		},
		{
			"test-ss://127.0.0.1:1",
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

func TestEngineBorrowsUpstream(t *testing.T) {
	var got Network
	RegisterLayer("borrowing", Spec{
		Kind:     KindProxy,
		Requires: Stream,
		Provides: Stream,
		Server: func(_ Transport, upstream Network, _ Options) (Server, error) {
			got = upstream
			return fakeServer{}, nil
		},
	})
	upstream := &closableNet{fakeNet{name: "upstream"}}
	if _, err := (Engine{Upstream: upstream}).Server(parse(t, "borrowing://127.0.0.1:1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(io.Closer); ok {
		t.Fatal("server received a closable upstream")
	}
	if b, ok := got.(borrowed); !ok || b.Network != Network(upstream) {
		t.Fatalf("server upstream = %#v, want the injected network borrowed", got)
	}
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
