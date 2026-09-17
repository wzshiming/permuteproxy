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
	if f, ok := n.(*fakeNet); ok {
		return f.name
	}
	if n == native {
		return "native"
	}
	return "?"
}

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
			return nil, nil
		},
	}
}

func init() {
	RegisterNetwork("cmd", NetworkSpec{Plane: Stream, AddressKind: AddressOpaque})
	RegisterNetwork("fakenet", NetworkSpec{Plane: Stream, Network: &fakeNet{name: "impl"}})
	RegisterLayer("tls", fakeAdapter("tls", Stream, Stream, "tls_skip_verify", "tls_self_signed"))
	RegisterLayer("snappy", fakeAdapter("snappy", Stream, Stream))
	RegisterLayer("quic", fakeAdapter("quic", Packet, Stream))
	RegisterLayer("http", fakeProxy("http", Stream, Stream, 0, "username", "password"))
	RegisterLayer("socks4", fakeProxy("socks4", Stream, Stream, 0, "username", ""))
	RegisterLayer("ssh", fakeProxy("ssh", Stream, Stream, 0, "username", "password", "identity_file"))
	RegisterLayer("socks5", fakeProxy("socks5", Stream, Stream|Packet, 0, "username", "password"))
	RegisterLayer("ss", fakeProxy("ss", 0, 0, Stream|Packet, "username", "password"))
	anyProxy := fakeProxy("any", Stream, Stream, 0, "username", "password")
	anyProxy.Client = nil
	RegisterLayer("any", anyProxy)
	RegisterAlias("https", "http+tls")
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
	mustPanic(t, "duplicate layer", func() { RegisterLayer("tls", adapter) })
	mustPanic(t, "layer named like network", func() { RegisterLayer("tcp", adapter) })
	mustPanic(t, "duplicate network", func() { RegisterNetwork("tcp", NetworkSpec{Plane: Stream}) })
	mustPanic(t, "alias named like layer", func() { RegisterAlias("tls", "http+tls") })
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
		{"ss auto dual", mk("", "ss"), true},
		{"ss over tls", mk("", "ss", "tls"), true},
		{"ss over udp", mk("udp", "ss"), true},
		{"quic over udp", mk("udp", "quic"), true},
		{"quic auto", mk("", "quic"), true},
		{"socks5 over quic", mk("", "socks5", "quic"), true},
		{"raw tcp", mk("tcp"), true},
		{"unix", Chain{Endpoint: Endpoint{Network: "unix", Address: "./x.sock"}}, true},
		{"quic over tcp", mk("tcp", "quic"), false},
		{"tls over udp", mk("udp", "tls"), false},
		{"proxy not outermost", mk("", "tls", "socks5"), false},
		{"unknown scheme", mk("", "xxx"), false},
		{"unknown network", mk("xxx", "tls"), false},
		{"unknown option", Chain{Layers: []Layer{{Scheme: "tls", Options: Options{"bogus": "1"}}}, Endpoint: Endpoint{Address: "127.0.0.1:1"}}, false},
		{"auto without layers", mk(""), false},
		{"empty address", Chain{Layers: []Layer{{Scheme: "tls"}}}, false},
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
