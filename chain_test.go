package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
)

var (
	callsMu sync.Mutex // a declared server's serves record from their own goroutines
	calls   []string
)

func record(format string, args ...interface{}) {
	callsMu.Lock()
	defer callsMu.Unlock()
	calls = append(calls, fmt.Sprintf(format, args...))
}

type fakeNet struct{ name string }

func (n *fakeNet) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	record("%s.dial %s %s", n.name, network, address)
	return nil, nil
}

func (n *fakeNet) Listen(_ context.Context, network, address string) (net.Listener, error) {
	record("%s.listen %s %s", n.name, network, address)
	return idleListener{}, nil
}

func (n *fakeNet) ListenPacket(_ context.Context, network, address string) (net.PacketConn, error) {
	record("%s.listenpacket %s %s", n.name, network, address)
	return idlePacketConn{}, nil
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

func taint(name string, opts Options) {
	if opts["seen"] != "" {
		record("%s.dirty", name)
	}
	opts["seen"] = "1"
}

// fakeAdapter provides one plane over the plane it requires, recording each call of its link.
func fakeAdapter(name string, requires, provides Plane, options ...string) Spec {
	return Spec{
		Kind:     KindAdapter,
		Requires: requires,
		Provides: provides,
		Options:  options,
		NewAdapter: func(opts Options) (*AdapterFuncs, error) {
			record("%s.new", name)
			taint(name, opts)
			link := &Link{Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
				record("%s.client", name)
				return carrier, nil
			}}
			if requires != provides {
				link.Over = requires
			}
			switch {
			case provides == Stream && requires == Stream:
				link.Listener = func(ln net.Listener) (net.Listener, error) { record("%s.listener", name); return ln, nil }
			case provides == Stream:
				link.PacketListener = func(net.PacketConn) (net.Listener, error) {
					record("%s.packetlistener", name)
					return idleListener{}, nil
				}
			case requires == Packet:
				link.PacketConn = func(pc net.PacketConn) (net.PacketConn, error) { record("%s.packetconn", name); return pc, nil }
			}
			if provides == Stream {
				return &AdapterFuncs{Stream: link}, nil
			}
			return &AdapterFuncs{Packet: link}, nil
		},
	}
}

// fakeProxy declares a proxy whose client and server functions record each call with what they are handed.
func fakeProxy(name string, requires, provides, preserves Plane, user, pass string, options ...string) Spec {
	return Spec{
		Kind:           KindProxy,
		Requires:       requires,
		Provides:       provides,
		Preserves:      preserves,
		Options:        options,
		UsernameOption: user,
		PasswordOption: pass,
		Networks:       []string{"tcp", "udp", "unixgram"},
		NewClient: func(opts Options) (*ClientFuncs, error) {
			record("%s.new", name)
			taint(name, opts)
			return &ClientFuncs{
				Dial: func(_ context.Context, inner Transport, network, address string) (net.Conn, error) {
					record("%s.dial %v %s %s", name, inner.Planes(), network, address)
					return nil, nil
				},
				ListenPacket: func(_ context.Context, inner Transport, local Network, network, address string) (net.PacketConn, error) {
					record("%s.listenpacket %v local=%s %s %s", name, inner.Planes(), netName(local), network, address)
					return nil, nil
				},
			}, nil
		},
		NewServer: func(opts Options) (*ServerFuncs, error) {
			record("%s.newserver", name)
			taint(name, opts)
			return &ServerFuncs{
				Serve: func(_ context.Context, _ net.Listener, upstream Network) error {
					record("%s.serve upstream=%s", name, netName(upstream))
					return nil
				},
				ServePacket: func(_ context.Context, _ net.PacketConn, upstream Network) error {
					record("%s.servepacket upstream=%s", name, netName(upstream))
					return nil
				},
			}, nil
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

// declared is an adapter whose NewAdapter returns funcs and err as given.
func declared(requires, provides Plane, funcs *AdapterFuncs, err error) Spec {
	return Spec{Kind: KindAdapter, Requires: requires, Provides: provides, NewAdapter: func(Options) (*AdapterFuncs, error) { return funcs, err }}
}

var (
	errDeclare         = errors.New("declare failed")
	errLink            = errors.New("link failed")
	failClient         = func(context.Context, net.Conn) (net.Conn, error) { return nil, errLink }
	failListener       = func(net.Listener) (net.Listener, error) { return nil, errLink }
	failPacketListener = func(net.PacketConn) (net.Listener, error) { return nil, errLink }
	failPacketConn     = func(net.PacketConn) (net.PacketConn, error) { return nil, errLink }
)

// failingLinks are layers whose link functions all fail, one per pair with a server form.
var failingLinks = map[string]Spec{
	"test-fail-ss": declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Client: failClient, Listener: failListener}}, nil),
	"test-fail-sp": declared(Packet, Stream, &AdapterFuncs{Stream: &Link{Over: Packet, Client: failClient, PacketListener: failPacketListener}}, nil),
	"test-fail-pp": declared(Packet, Packet, &AdapterFuncs{Packet: &Link{Client: failClient, PacketConn: failPacketConn}}, nil),
}

// recordedCloses is a base whose carriers record their Close.
var recordedCloses = NetworkFuncs{
	DialContextFunc:  func(context.Context, string, string) (net.Conn, error) { return closeConn{}, nil },
	ListenFunc:       func(context.Context, string, string) (net.Listener, error) { return closeListener{}, nil },
	ListenPacketFunc: func(context.Context, string, string) (net.PacketConn, error) { return closePacketConn{}, nil },
}

type closeConn struct{ net.Conn }

func (closeConn) Close() error { record("carrier.close"); return nil }

type closeListener struct{ net.Listener }

func (closeListener) Close() error { record("carrier.close"); return nil }

type closePacketConn struct{ net.PacketConn }

func (closePacketConn) Close() error { record("carrier.close"); return nil }

// idleListener and idlePacketConn are carriers a server can hold and close without any I/O.
type idleListener struct{ net.Listener }

func (idleListener) Close() error { return nil }

type idlePacketConn struct{ net.PacketConn }

func (idlePacketConn) Close() error { return nil }

// uncovered are layers whose links do not cover the planes they declare.
var uncovered = map[string]Spec{
	"test-bad-missing": declared(Stream, Stream, &AdapterFuncs{}, nil),
	"test-bad-extra":   declared(Stream, Stream, &AdapterFuncs{Stream: &Link{}, Packet: &Link{}}, nil),
	"test-bad-carrier": declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Over: Packet}}, nil),
	"test-bad-dual":    declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Over: Stream | Packet}}, nil),
	"test-bad-bit":     declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Over: 4}}, nil),
	"test-bad-ss-form": declared(Stream, Stream, &AdapterFuncs{Stream: &Link{PacketListener: failPacketListener}}, nil),
	"test-bad-sp-form": declared(Packet, Stream, &AdapterFuncs{Stream: &Link{Over: Packet, Listener: failListener}}, nil),
	"test-bad-pp-form": declared(Packet, Packet, &AdapterFuncs{Packet: &Link{PacketListener: failPacketListener}}, nil),
	"test-bad-ps-form": declared(Stream, Packet, &AdapterFuncs{Packet: &Link{Over: Stream, PacketConn: failPacketConn}}, nil),
}

// declaredProxy is a proxy over Stream whose NewClient returns funcs and err as given.
func declaredProxy(provides, preserves Plane, funcs *ClientFuncs, err error) Spec {
	return Spec{Kind: KindProxy, Requires: Stream, Provides: provides, Preserves: preserves, Networks: []string{"tcp", "udp"}, NewClient: func(Options) (*ClientFuncs, error) { return funcs, err }}
}

// failDial and failListenPacket fill client functions that fixtures must declare but do not exercise.
var (
	failDial         = func(context.Context, Transport, string, string) (net.Conn, error) { return nil, errLink }
	failListenPacket = func(context.Context, Transport, Network, string, string) (net.PacketConn, error) { return nil, errLink }
)

// uncoveredClients are proxies whose ClientFuncs miss the function a plane they declare needs.
var uncoveredClients = map[string]Spec{
	"test-client-no-dial":        declaredProxy(Stream, 0, &ClientFuncs{ListenPacket: failListenPacket}, nil),
	"test-client-kept-no-dial":   declaredProxy(0, Stream, &ClientFuncs{ListenPacket: failListenPacket}, nil),
	"test-client-no-packet":      declaredProxy(Packet, 0, &ClientFuncs{Dial: failDial}, nil),
	"test-client-kept-no-packet": declaredProxy(0, Packet, &ClientFuncs{Dial: failDial}, nil),
}

// declaredServer is a proxy providing Stream over the planes it requires or preserves, whose NewServer returns funcs and err as given.
func declaredServer(requires, preserves Plane, funcs *ServerFuncs, err error) Spec {
	return Spec{Kind: KindProxy, Requires: requires, Provides: Stream, Preserves: preserves, NewServer: func(Options) (*ServerFuncs, error) { return funcs, err }}
}

// failServe and failServePacket fill server functions that fixtures must declare but do not exercise.
var (
	failServe       = func(context.Context, net.Listener, Network) error { return errLink }
	failServePacket = func(context.Context, net.PacketConn, Network) error { return errLink }
)

// uncoveredServers are proxies whose ServerFuncs miss the function a plane they require or preserve needs.
var uncoveredServers = map[string]Spec{
	"test-server-no-serve":       declaredServer(Stream, 0, &ServerFuncs{ServePacket: failServePacket}, nil),
	"test-server-kept-no-serve":  declaredServer(0, Stream, &ServerFuncs{ServePacket: failServePacket}, nil),
	"test-server-no-packet":      declaredServer(Packet, 0, &ServerFuncs{Serve: failServe}, nil),
	"test-server-kept-no-packet": declaredServer(0, Packet, &ServerFuncs{Serve: failServe}, nil),
}

// Fixtures carry a test- prefix so the root test binary can link the real protocol packages.
func init() {
	RegisterNetwork("test-cmd", NetworkSpec{Plane: Stream, AddressKind: AddressOpaque})
	RegisterNetwork("fakenet", NetworkSpec{Plane: Stream, Network: &fakeNet{name: "impl"}})
	RegisterLayer("test-tls", fakeAdapter("test-tls", Stream, Stream, "tls_skip_verify", "tls_self_signed", "tls_cert_file", "tls_key_file"))
	RegisterLayer("test-snappy", fakeAdapter("test-snappy", Stream, Stream))
	RegisterLayer("test-quic", fakeAdapter("test-quic", Packet, Stream))
	RegisterLayer("test-dtls", fakeAdapter("test-dtls", Packet, Packet))
	RegisterLayer("test-uot", fakeAdapter("test-uot", Stream, Packet))
	keep := fakeAdapter("test-keep", Stream, Stream)
	keep.Preserves = Packet
	RegisterLayer("test-keep", keep)
	RegisterLayer("test-http", fakeProxy("test-http", Stream, Stream, 0, "username", "password"))
	RegisterLayer("test-socks4", fakeProxy("test-socks4", Stream, Stream, 0, "username", ""))
	RegisterLayer("test-ssh", fakeProxy("test-ssh", Stream, Stream, 0, "username", "password", "identity_file", "identity_data", "authorized_data"))
	RegisterLayer("test-socks5", fakeProxy("test-socks5", Stream, Stream|Packet, 0, "username", "password"))
	RegisterLayer("test-ss", fakeProxy("test-ss", 0, 0, Stream|Packet, "username", "password"))
	anyProxy := fakeProxy("test-any", Stream, Stream, 0, "username", "password")
	anyProxy.NewClient, anyProxy.Networks = nil, nil
	RegisterLayer("test-any", anyProxy)
	// test-legacy keeps the Client and Server forms, handing back its base and a fakeServer.
	RegisterLayer("test-legacy", Spec{
		Kind:      KindProxy,
		Preserves: Stream | Packet,
		Client: func(inner Transport, base Network, _ Options) (Network, error) {
			record("test-legacy.client %v", inner.Planes())
			return base, nil
		},
		Server: func(inner Transport, upstream Network, _ Options) (Server, error) {
			record("test-legacy.server %v upstream=%s", inner.Planes(), netName(upstream))
			return fakeServer{}, nil
		},
	})
	// test-peer resolves the default peer of its udp dials and binds their sockets through local.
	RegisterLayer("test-peer", Spec{Kind: KindProxy, Requires: Stream, Provides: Packet, Networks: []string{"udp"}, NewClient: func(Options) (*ClientFuncs, error) {
		return &ClientFuncs{
			ListenPacket: func(ctx context.Context, _ Transport, local Network, network, address string) (net.PacketConn, error) {
				record("test-peer.listenpacket %s %s", network, address)
				return local.ListenPacket(ctx, network, address)
			},
			Peer: func(_ context.Context, network, address string) (net.Addr, error) {
				record("test-peer.peer %s %s", network, address)
				return net.ResolveUDPAddr(network, address)
			},
		}, nil
	}})
	RegisterLayer("wide", wideAdapter())
	// test-nil-adapt and test-nil-legacy keep the Adapt, Client and Server forms, each returning nil, nil.
	RegisterLayer("test-nil-adapt", Spec{Kind: KindAdapter, Requires: Stream, Provides: Stream, Adapt: func(Transport, Options) (Transport, error) { return nil, nil }})
	RegisterLayer("test-nil-legacy", Spec{
		Kind:     KindProxy,
		Requires: Stream,
		Provides: Stream,
		Client:   func(Transport, Network, Options) (Network, error) { return nil, nil },
		Server:   func(Transport, Network, Options) (Server, error) { return nil, nil },
	})
	RegisterLayer("niladapter", declared(Stream, Stream, nil, nil))
	RegisterLayer("test-broken", declared(Stream, Stream, nil, errDeclare))
	for name, spec := range uncovered {
		RegisterLayer(name, spec)
	}
	RegisterLayer("test-bare-ss", declared(Stream, Stream, &AdapterFuncs{Stream: &Link{}}, nil))
	RegisterLayer("test-bare-sp", declared(Packet, Stream, &AdapterFuncs{Stream: &Link{Over: Packet}}, nil))
	RegisterLayer("test-bare-pp", declared(Packet, Packet, &AdapterFuncs{Packet: &Link{}}, nil))
	RegisterLayer("test-bare-ps", declared(Stream, Packet, &AdapterFuncs{Packet: &Link{Over: Stream}}, nil))
	for name, spec := range failingLinks {
		RegisterLayer(name, spec)
	}
	RegisterLayer("closable", declared(Stream, Stream, &AdapterFuncs{Stream: &Link{}, Close: func() error { record("closable.close"); return nil }}, nil))
	RegisterLayer("closableproxy", declaredProxy(Stream, 0, &ClientFuncs{Dial: failDial, Close: func() error { record("closableproxy.close"); return nil }}, nil))
	RegisterLayer("closableserver", declaredServer(Stream, 0, &ServerFuncs{Serve: failServe, Close: func() error { record("closableserver.close"); return nil }}, nil))
	RegisterLayer("nilproxy", Spec{
		Kind:      KindProxy,
		Requires:  Stream,
		Provides:  Stream,
		Networks:  []string{"tcp"},
		NewClient: func(Options) (*ClientFuncs, error) { return nil, nil },
		NewServer: func(Options) (*ServerFuncs, error) { return nil, nil },
	})
	RegisterLayer("test-client-broken", declaredProxy(Stream, 0, nil, errDeclare))
	for name, spec := range uncoveredClients {
		RegisterLayer(name, spec)
	}
	RegisterLayer("test-server-broken", declaredServer(Stream, 0, nil, errDeclare))
	for name, spec := range uncoveredServers {
		RegisterLayer(name, spec)
	}
	// test-reject-* declare a Close but miss the function the plane they declare needs.
	RegisterLayer("test-reject-adapter", declared(Stream, Stream, &AdapterFuncs{Close: func() error { record("test-reject-adapter.close"); return nil }}, nil))
	RegisterLayer("test-reject-client", declaredProxy(Stream, 0, &ClientFuncs{Close: func() error { record("test-reject-client.close"); return nil }}, nil))
	RegisterLayer("test-reject-server", declaredServer(Stream, 0, &ServerFuncs{Close: func() error { record("test-reject-server.close"); return nil }}, nil))
	// test-packet-server binds only a Packet carrier, so a Stream one leaves it nothing to serve.
	RegisterLayer("test-packet-server", Spec{Kind: KindProxy, Provides: Stream, Preserves: Packet, NewServer: func(Options) (*ServerFuncs, error) {
		record("test-packet-server.newserver")
		return &ServerFuncs{ServePacket: func(_ context.Context, _ net.PacketConn, upstream Network) error {
			record("test-packet-server.servepacket upstream=%s", netName(upstream))
			return nil
		}}, nil
	}})
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
	mustPanic(t, "adapter without Adapt or NewAdapter", func() { RegisterLayer("na", Spec{Requires: Stream, Provides: Stream}) })
	adapt := wideAdapter().Adapt
	mustPanic(t, "proxy with Adapt", func() {
		RegisterLayer("pa", Spec{Kind: KindProxy, Requires: Stream, Provides: Stream, Adapt: adapt})
	})
	mustPanic(t, "adapter with Adapt and NewAdapter", func() {
		RegisterLayer("both", Spec{Requires: Stream, Provides: Stream, Adapt: adapt, NewAdapter: adapter.NewAdapter})
	})
	mustPanic(t, "proxy with NewAdapter", func() {
		proxy := fakeProxy("pn", Stream, Stream, 0, "", "")
		proxy.NewAdapter = adapter.NewAdapter
		RegisterLayer("pn", proxy)
	})
	mustPanic(t, "layer consuming nothing", func() { RegisterLayer("ln", Spec{Provides: Stream, NewAdapter: adapter.NewAdapter}) })
	mustPanic(t, "password without username", func() {
		RegisterLayer("pw", Spec{Requires: Stream, Provides: Stream, PasswordOption: "p", NewAdapter: adapter.NewAdapter})
	})
	for name, spec := range map[string]Spec{
		"requires":  {Requires: 4, Provides: Stream, NewAdapter: adapter.NewAdapter},
		"provides":  {Requires: Stream, Provides: 4, NewAdapter: adapter.NewAdapter},
		"preserves": {Requires: Stream, Provides: Stream, Preserves: 4, NewAdapter: adapter.NewAdapter},
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
	for _, name := range []string{"na", "both", "pn"} {
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
}

func TestRegisterRejectsClientDeclarations(t *testing.T) {
	proxy := fakeProxy("pc", Stream, Stream, 0, "", "")
	twice, unlisted, listed, unknown, variant, adapter := proxy, proxy, proxy, proxy, proxy, fakeAdapter("ac", Stream, Stream)
	twice.Client = func(Transport, Network, Options) (Network, error) { return nil, nil }
	unlisted.Networks = nil
	listed.NewClient = nil
	unknown.Networks = []string{"tcp", "bogus"}
	variant.Networks = []string{"udp", "tcp4"}
	adapter.NewClient, adapter.Networks = proxy.NewClient, proxy.Networks
	for name, spec := range map[string]Spec{
		"client-twice":    twice,
		"client-unlisted": unlisted,
		"client-listed":   listed,
		"client-unknown":  unknown,
		"client-variant":  variant,
		"client-adapter":  adapter,
	} {
		mustPanic(t, name, func() { RegisterLayer(name, spec) })
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
}

func TestRegisterRejectsServerDeclarations(t *testing.T) {
	proxy := fakeProxy("ps", Stream, Stream, 0, "", "")
	twice, adapter := proxy, fakeAdapter("as", Stream, Stream)
	twice.Server = func(Transport, Network, Options) (Server, error) { return fakeServer{}, nil }
	adapter.NewServer = proxy.NewServer
	for name, spec := range map[string]Spec{
		"server-twice":   twice,
		"server-adapter": adapter,
		"server-none":    {Kind: KindProxy, Requires: Stream, Provides: Stream},
	} {
		mustPanic(t, name, func() { RegisterLayer(name, spec) })
		if _, ok := lookupLayer(name); ok {
			t.Fatalf("rejected layer %q was registered", name)
		}
	}
}

func TestRegisterCopiesNetworks(t *testing.T) {
	calls = nil
	networks := []string{"tcp"}
	spec := fakeProxy("test-copied", Stream, Stream, 0, "", "")
	spec.Networks = networks
	RegisterLayer("test-copied", spec)
	networks[0] = "unix"
	n, err := Engine{Base: &fakeNet{name: "base"}}.Client(mk("", "test-copied"))
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := n.DialContext(context.Background(), "unix", "x:1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unix dial after the caller changed its slice = %v, want ErrUnsupported", err)
	}
	assertCalls(t)
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
