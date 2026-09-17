package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

var calls []string

func record(format string, args ...interface{}) {
	calls = append(calls, fmt.Sprintf(format, args...))
}

type fakeNet struct{ name string }

func (n *fakeNet) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	record("%s.dial %s %s", n.name, network, address)
	return nil, nil
}

func (n *fakeNet) Listen(_ context.Context, network, address string) (net.Listener, error) {
	record("%s.listen %s %s", n.name, network, address)
	return nil, nil
}

func (n *fakeNet) ListenPacket(_ context.Context, network, address string) (net.PacketConn, error) {
	record("%s.listenpacket %s %s", n.name, network, address)
	return nil, nil
}

func netName(n Network) string {
	if b, ok := n.(borrowed); ok {
		n = b.Network
	}
	if f, ok := n.(*fakeNet); ok {
		return f.name
	}
	if n == native {
		return "native"
	}
	return "?"
}

type fakeServer struct{}

func (fakeServer) Run(context.Context) error { return nil }

func (fakeServer) Close() error { return nil }

type closableNet struct{ fakeNet }

func (n *closableNet) Close() error { record("%s.close", n.name); return nil }

type closableTransport struct {
	Transport
	name string
}

func (t closableTransport) Close() error { record("%s.close", t.name); return nil }

func taint(name string, opts Options) {
	if opts["seen"] != "" {
		record("%s.dirty", name)
	}
	opts["seen"] = "1"
}

func fakeAdapter(name string, requires, provides Plane, options ...string) Spec {
	return Spec{
		Kind:     KindAdapter,
		Requires: requires,
		Provides: provides,
		Options:  options,
		Adapt: func(inner Transport, opts Options) (Transport, error) {
			record("%s.adapt %v", name, inner.Planes())
			taint(name, opts)
			return TransportFuncs{
				Plane: provides,
				DialFunc: func(ctx context.Context, _ Plane) (net.Conn, error) {
					return inner.Dial(ctx, requires)
				},
				ListenFunc: func(ctx context.Context) (net.Listener, error) {
					if requires == Packet {
						_, err := inner.ListenPacket(ctx)
						return nil, err
					}
					return inner.Listen(ctx)
				},
			}, nil
		},
	}
}

func fakeProxy(name string, requires, provides, preserves Plane, user, pass string, options ...string) Spec {
	return Spec{
		Kind:           KindProxy,
		Requires:       requires,
		Provides:       provides,
		Preserves:      preserves,
		Options:        options,
		UsernameOption: user,
		PasswordOption: pass,
		Client: func(inner Transport, base Network, opts Options) (Network, error) {
			record("%s.client %v base=%s", name, inner.Planes(), netName(base))
			taint(name, opts)
			return base, nil
		},
		Server: func(inner Transport, upstream Network, opts Options) (Server, error) {
			record("%s.server %v upstream=%s", name, inner.Planes(), netName(upstream))
			taint(name, opts)
			return fakeServer{}, nil
		},
	}
}

// wideAdapter declares Stream but hands back a transport exposing both planes.
func wideAdapter() Spec {
	return Spec{
		Kind:     KindAdapter,
		Requires: Stream,
		Provides: Stream,
		Adapt: func(inner Transport, _ Options) (Transport, error) {
			record("wide.adapt %v", inner.Planes())
			return TransportFuncs{
				Plane:            Stream | Packet,
				DialFunc:         func(_ context.Context, plane Plane) (net.Conn, error) { record("wide.dial %v", plane); return nil, nil },
				ListenFunc:       func(context.Context) (net.Listener, error) { record("wide.listen"); return nil, nil },
				ListenPacketFunc: func(context.Context) (net.PacketConn, error) { record("wide.listenpacket"); return nil, nil },
			}, nil
		},
	}
}

// Fixtures carry a test- prefix so the root test binary can link the real protocol packages.
func init() {
	RegisterNetwork("test-cmd", NetworkSpec{Plane: Stream, AddressKind: AddressOpaque})
	RegisterNetwork("fakenet", NetworkSpec{Plane: Stream, Network: &fakeNet{name: "impl"}})
	RegisterLayer("test-tls", fakeAdapter("test-tls", Stream, Stream, "tls_skip_verify", "tls_self_signed", "tls_cert_file", "tls_key_file"))
	RegisterLayer("test-snappy", fakeAdapter("test-snappy", Stream, Stream))
	RegisterLayer("test-quic", fakeAdapter("test-quic", Packet, Stream))
	RegisterLayer("test-http", fakeProxy("test-http", Stream, Stream, 0, "username", "password"))
	RegisterLayer("test-socks4", fakeProxy("test-socks4", Stream, Stream, 0, "username", ""))
	RegisterLayer("test-ssh", fakeProxy("test-ssh", Stream, Stream, 0, "username", "password", "identity_file", "identity_data", "authorized_data"))
	RegisterLayer("test-socks5", fakeProxy("test-socks5", Stream, Stream|Packet, 0, "username", "password"))
	RegisterLayer("test-ss", fakeProxy("test-ss", 0, 0, Stream|Packet, "username", "password"))
	anyProxy := fakeProxy("test-any", Stream, Stream, 0, "username", "password")
	anyProxy.Client = nil
	RegisterLayer("test-any", anyProxy)
	RegisterLayer("wide", wideAdapter())
	RegisterLayer("niladapter", Spec{Kind: KindAdapter, Requires: Stream, Provides: Stream, Adapt: func(Transport, Options) (Transport, error) { return nil, nil }})
	RegisterLayer("closable", Spec{Kind: KindAdapter, Requires: Stream, Provides: Stream, Adapt: func(inner Transport, _ Options) (Transport, error) {
		return closableTransport{inner, "closable"}, nil
	}})
	RegisterLayer("closableproxy", Spec{Kind: KindProxy, Requires: Stream, Provides: Stream, Client: func(Transport, Network, Options) (Network, error) {
		return &closableNet{fakeNet{name: "closableproxy"}}, nil
	}})
	RegisterLayer("nilproxy", Spec{
		Kind:     KindProxy,
		Requires: Stream,
		Provides: Stream,
		Client:   func(Transport, Network, Options) (Network, error) { return nil, nil },
		Server:   func(Transport, Network, Options) (Server, error) { return nil, nil },
	})
	RegisterAlias("test-https", "test-http+test-tls")
	RegisterAlias("later", "pending+test-tls")
}

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic", name)
		}
	}()
	f()
}

func TestRegisterRejects(t *testing.T) {
	adapter := fakeAdapter("x", Stream, Stream)
	mustPanic(t, "duplicate layer", func() { RegisterLayer("test-tls", adapter) })
	mustPanic(t, "layer named like network", func() { RegisterLayer("tcp", adapter) })
	mustPanic(t, "duplicate network", func() { RegisterNetwork("tcp", NetworkSpec{Plane: Stream}) })
	mustPanic(t, "alias named like layer", func() { RegisterAlias("test-tls", "test-http+test-tls") })
	mustPanic(t, "name with plus", func() { RegisterLayer("a+b", adapter) })
	mustPanic(t, "network without plane", func() { RegisterNetwork("np", NetworkSpec{}) })
	mustPanic(t, "adapter without Adapt", func() { RegisterLayer("na", Spec{Requires: Stream, Provides: Stream}) })
	mustPanic(t, "proxy with Adapt", func() {
		RegisterLayer("pa", Spec{Kind: KindProxy, Requires: Stream, Provides: Stream, Adapt: adapter.Adapt})
	})
	mustPanic(t, "layer consuming nothing", func() { RegisterLayer("ln", Spec{Provides: Stream, Adapt: adapter.Adapt}) })
	mustPanic(t, "password without username", func() {
		RegisterLayer("pw", Spec{Requires: Stream, Provides: Stream, PasswordOption: "p", Adapt: adapter.Adapt})
	})
	for name, spec := range map[string]Spec{
		"requires":  {Requires: 4, Provides: Stream, Adapt: adapter.Adapt},
		"provides":  {Requires: Stream, Provides: 4, Adapt: adapter.Adapt},
		"preserves": {Requires: Stream, Provides: Stream, Preserves: 4, Adapt: adapter.Adapt},
	} {
		mustPanic(t, "unknown plane bit in "+name, func() { RegisterLayer("bit."+name, spec) })
	}
	for _, name := range []string{"Upper", "cmd_nc", "1bad", "a b", "-x", ".x"} {
		mustPanic(t, "name "+name, func() { RegisterLayer(name, adapter) })
	}
	RegisterLayer("ok.name-1", adapter)
	mustPanic(t, "dual-plane network", func() { RegisterNetwork("dual", NetworkSpec{Plane: Stream | Packet}) })
	mustPanic(t, "nested alias", func() { RegisterAlias("nested", "test-https+tcp") })
	mustPanic(t, "self alias", func() { RegisterAlias("self", "self") })
	mustPanic(t, "alias with malformed token", func() { RegisterAlias("bad", "HTTP+test-tls") })
	mustPanic(t, "alias named like an expansion token", func() { RegisterAlias("pending", "test-snappy") })
	if _, ok := lookupLayer("na"); ok {
		t.Fatal("rejected layer was registered")
	}
}

func mk(network string, schemes ...string) Chain {
	c := Chain{Endpoint: Endpoint{Network: network, Address: "127.0.0.1:1"}}
	for _, s := range schemes {
		c.Layers = append(c.Layers, Layer{Scheme: s})
	}
	return c
}

func TestChainValidate(t *testing.T) {
	tests := []struct {
		name  string
		chain Chain
		ok    bool
	}{
		{"ss auto dual", mk("", "test-ss"), true},
		{"ss over tls", mk("", "test-ss", "test-tls"), true},
		{"ss over udp", mk("udp", "test-ss"), true},
		{"quic over udp", mk("udp", "test-quic"), true},
		{"quic auto", mk("", "test-quic"), true},
		{"socks5 over quic", mk("", "test-socks5", "test-quic"), true},
		{"raw tcp", mk("tcp"), true},
		{"unix", Chain{Endpoint: Endpoint{Network: "unix", Address: "./x.sock"}}, true},
		{"quic over tcp", mk("tcp", "test-quic"), false},
		{"tls over udp", mk("udp", "test-tls"), false},
		{"proxy not outermost", mk("", "test-tls", "test-socks5"), false},
		{"unknown scheme", mk("", "xxx"), false},
		{"unknown network", mk("xxx", "test-tls"), false},
		{"unknown option", Chain{Layers: []Layer{{Scheme: "test-tls", Options: Options{"bogus": "1"}}}, Endpoint: Endpoint{Address: "127.0.0.1:1"}}, false},
		{"auto without layers", mk(""), false},
		{"empty address", Chain{Layers: []Layer{{Scheme: "test-tls"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.chain.Validate()
			if tt.ok != (err == nil) {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("Validate() = %v, want ErrInvalidChain", err)
			}
		})
	}
}
