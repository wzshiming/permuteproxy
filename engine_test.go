package permuteproxy

import (
	"context"
	"errors"
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
	base, upstream := &fakeNet{name: "base"}, &fakeNet{name: "upstream"}
	e := Engine{Base: base, Upstream: upstream}
	tests := []struct {
		uri    string
		client string
		server string
	}{
		{"ss://127.0.0.1:1", "ss.client stream|packet base=base", "ss.server stream|packet upstream=upstream"},
		{"ss+tls://127.0.0.1:1", "ss.client stream base=base", "ss.server stream upstream=upstream"},
		{"ss+udp://127.0.0.1:1", "ss.client packet base=base", "ss.server packet upstream=upstream"},
		{"socks5+quic://127.0.0.1:1", "socks5.client stream base=base", "socks5.server stream upstream=upstream"},
		{"http://u:p@127.0.0.1:1", "http.client stream base=base", "http.server stream upstream=upstream"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			c := parse(t, tt.uri)
			n, err := e.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			if n != Network(base) {
				t.Fatalf("Client() returned %v, want the base passed to the constructor", n)
			}
			if _, err := e.Server(c); err != nil {
				t.Fatal(err)
			}
			var want []string
			if len(c.Layers) > 1 {
				want = append(want, c.Layers[1].Scheme+".adapt "+adapterCarrier(c))
			}
			want = append(want, tt.client)
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
	tr, err = Engine{}.Transport(mk("tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := tr.(*bound); !ok || b.network != native {
		t.Fatalf("zero Engine bound %#v, want native", tr)
	}
}
