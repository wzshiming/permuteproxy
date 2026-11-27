package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
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
	if l, ok := n.(*lossyNet); ok {
		return l.name
	}
	if _, ok := n.(byName); ok {
		return "default"
	}
	return "?"
}

type closableNet struct{ fakeNet }

func (n *closableNet) Close() error { record("%s.close", n.name); return nil }

// lossyNet is a fakeNet whose listed networks lose datagram boundaries.
type lossyNet struct {
	fakeNet
	lossy []string
}

func (n *lossyNet) Lossy(network string) bool { return slices.Contains(n.lossy, network) }

func taint(name string, opts Options) {
	if opts["seen"] != "" {
		record("%s.dirty", name)
	}
	opts["seen"] = "1"
}

// fakeAdapter provides one plane over the plane it requires, recording each call of its link.
func fakeAdapter(name string, requires, provides Plane, options ...string) LayerSpec {
	return LayerSpec{
		Requires:   requires,
		Provides:   provides,
		OptionKeys: options,
		NewAdapter: func(opts Options) (*AdapterFuncs, error) {
			record("%s.new", name)
			taint(name, opts)
			link := &Link{Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
				conn, err := carrier(ctx)
				if err != nil {
					return nil, err
				}
				record("%s.client", name)
				return conn, nil
			}}
			if requires != provides {
				link.Over = requires
			}
			switch {
			case provides == Stream && requires == Stream:
				link.Listen = func(ctx context.Context, carrier func(context.Context) (net.Listener, error)) (net.Listener, error) {
					ln, err := carrier(ctx)
					if err != nil {
						return nil, err
					}
					record("%s.listener", name)
					return ln, nil
				}
			case provides == Stream:
				link.ListenPacket = func(ctx context.Context, carrier func(context.Context) (net.PacketConn, error)) (net.Listener, error) {
					if _, err := carrier(ctx); err != nil {
						return nil, err
					}
					record("%s.packetlistener", name)
					return idleListener{}, nil
				}
			}
			if provides == Stream {
				return &AdapterFuncs{Stream: link}, nil
			}
			return &AdapterFuncs{Packet: link}, nil
		},
	}
}

// fakeProxy declares a proxy whose client and server functions record each call with what they are handed.
func fakeProxy(name string, requires, provides, preserves Plane, user, pass string, options ...string) LayerSpec {
	return LayerSpec{
		Requires:    requires,
		Provides:    provides,
		Preserves:   preserves,
		OptionKeys:  options,
		UsernameKey: user,
		PasswordKey: pass,
		Networks:    []string{"tcp", "udp", "unixgram"},
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

// declared is an adapter whose NewAdapter returns funcs and err as given.
func declared(requires, provides Plane, funcs *AdapterFuncs, err error) LayerSpec {
	return LayerSpec{Requires: requires, Provides: provides, NewAdapter: func(Options) (*AdapterFuncs, error) { return funcs, err }}
}

var (
	errDeclare = errors.New("declare failed")
	errLink    = errors.New("link failed")
	// The fail* links obtain a carrier, close it as its owner, then fail.
	failDialLink = func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
		if conn, err := carrier(ctx); err == nil {
			conn.Close()
		}
		return nil, errLink
	}
	failListen = func(ctx context.Context, carrier func(context.Context) (net.Listener, error)) (net.Listener, error) {
		if ln, err := carrier(ctx); err == nil {
			ln.Close()
		}
		return nil, errLink
	}
	failListenOverPacket = func(ctx context.Context, carrier func(context.Context) (net.PacketConn, error)) (net.Listener, error) {
		if pc, err := carrier(ctx); err == nil {
			pc.Close()
		}
		return nil, errLink
	}
)

// failingLinks are layers whose link functions all fail, one per pair with a server form.
var failingLinks = map[string]LayerSpec{
	"test-fail-ss": declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Dial: failDialLink, Listen: failListen}}, nil),
	"test-fail-sp": declared(Packet, Stream, &AdapterFuncs{Stream: &Link{Over: Packet, Dial: failDialLink, ListenPacket: failListenOverPacket}}, nil),
}

var errCheck = errors.New("check failed")

// checkingAdapter is fakeAdapter whose link functions record a check before they obtain their carrier and return err from it.
func checkingAdapter(name string, requires, provides Plane, err error) LayerSpec {
	spec := fakeAdapter(name, requires, provides)
	newAdapter := spec.NewAdapter
	spec.NewAdapter = func(opts Options) (*AdapterFuncs, error) {
		funcs, _ := newAdapter(opts)
		link := funcs.link(provides)
		if dial := link.Dial; dial != nil {
			link.Dial = func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
				if record("%s.checkdial", name); err != nil {
					return nil, err
				}
				return dial(ctx, carrier)
			}
		}
		if listen := link.Listen; listen != nil {
			link.Listen = func(ctx context.Context, carrier func(context.Context) (net.Listener, error)) (net.Listener, error) {
				if record("%s.checklisten", name); err != nil {
					return nil, err
				}
				return listen(ctx, carrier)
			}
		}
		if listen := link.ListenPacket; listen != nil {
			link.ListenPacket = func(ctx context.Context, carrier func(context.Context) (net.PacketConn, error)) (net.Listener, error) {
				if record("%s.checklisten", name); err != nil {
					return nil, err
				}
				return listen(ctx, carrier)
			}
		}
		return funcs, nil
	}
	return spec
}

// keepingAdapter provides Stream over Packet through a Dial that obtains a carrier for its first dial and keeps it for the later ones.
func keepingAdapter(name string) LayerSpec {
	return LayerSpec{Requires: Packet, Provides: Stream, NewAdapter: func(Options) (*AdapterFuncs, error) {
		var kept net.Conn
		return &AdapterFuncs{
			Stream: &Link{Over: Packet, Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
				record("%s.dial", name)
				if kept == nil {
					var err error
					if kept, err = carrier(ctx); err != nil {
						return nil, err
					}
				}
				return kept, nil
			}},
		}, nil
	}}
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
var uncovered = map[string]LayerSpec{
	"test-bad-missing": declared(Stream, Stream, &AdapterFuncs{}, nil),
	"test-bad-extra":   declared(Stream, Stream, &AdapterFuncs{Stream: &Link{}, Packet: &Link{}}, nil),
	"test-bad-carrier": declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Over: Packet}}, nil),
	"test-bad-dual":    declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Over: Stream | Packet}}, nil),
	"test-bad-bit":     declared(Stream, Stream, &AdapterFuncs{Stream: &Link{Over: 4}}, nil),
	"test-bad-ss-form": declared(Stream, Stream, &AdapterFuncs{Stream: &Link{ListenPacket: failListenOverPacket}}, nil),
	"test-bad-sp-form": declared(Packet, Stream, &AdapterFuncs{Stream: &Link{Over: Packet, Listen: failListen}}, nil),
	"test-bad-pp-form": declared(Packet, Packet, &AdapterFuncs{Packet: &Link{ListenPacket: failListenOverPacket}}, nil),
	"test-bad-ps-form": declared(Stream, Packet, &AdapterFuncs{Packet: &Link{Over: Stream, Listen: failListen}}, nil),
}

// declaredProxy is a proxy over Stream whose NewClient returns funcs and err as given.
func declaredProxy(provides, preserves Plane, funcs *ClientFuncs, err error) LayerSpec {
	return LayerSpec{Requires: Stream, Provides: provides, Preserves: preserves, Networks: []string{"tcp", "udp"}, NewClient: func(Options) (*ClientFuncs, error) { return funcs, err }}
}

// failDial and failListenPacket fill client functions that fixtures must declare but do not exercise.
var (
	failDial         = func(context.Context, Transport, string, string) (net.Conn, error) { return nil, errLink }
	failListenPacket = func(context.Context, Transport, Network, string, string) (net.PacketConn, error) { return nil, errLink }
)

// uncoveredClients are proxies whose ClientFuncs miss the function a plane they declare needs.
var uncoveredClients = map[string]LayerSpec{
	"test-client-no-dial":        declaredProxy(Stream, 0, &ClientFuncs{ListenPacket: failListenPacket}, nil),
	"test-client-kept-no-dial":   declaredProxy(0, Stream, &ClientFuncs{ListenPacket: failListenPacket}, nil),
	"test-client-no-packet":      declaredProxy(Packet, 0, &ClientFuncs{Dial: failDial}, nil),
	"test-client-kept-no-packet": declaredProxy(0, Packet, &ClientFuncs{Dial: failDial}, nil),
}

// declaredServer is a proxy providing Stream over the planes it requires or preserves, whose NewServer returns funcs and err as given.
func declaredServer(requires, preserves Plane, funcs *ServerFuncs, err error) LayerSpec {
	return LayerSpec{Requires: requires, Provides: Stream, Preserves: preserves, NewServer: func(Options) (*ServerFuncs, error) { return funcs, err }}
}

// failServe and failServePacket fill server functions that fixtures must declare but do not exercise.
var (
	failServe       = func(context.Context, net.Listener, Network) error { return errLink }
	failServePacket = func(context.Context, net.PacketConn, Network) error { return errLink }
)

// uncoveredServers are proxies whose ServerFuncs miss the function a plane they require or preserve needs.
var uncoveredServers = map[string]LayerSpec{
	"test-server-no-serve":       declaredServer(Stream, 0, &ServerFuncs{ServePacket: failServePacket}, nil),
	"test-server-kept-no-serve":  declaredServer(0, Stream, &ServerFuncs{ServePacket: failServePacket}, nil),
	"test-server-no-packet":      declaredServer(Packet, 0, &ServerFuncs{Serve: failServe}, nil),
	"test-server-kept-no-packet": declaredServer(0, Packet, &ServerFuncs{Serve: failServe}, nil),
}

// atRootInit is what the registry holds once the root package has initialized, before any fixture registers.
var atRootInit struct {
	networks map[string]NetworkSpec
	layers   map[string]LayerSpec
	aliases  map[string][]string
}

func init() {
	atRootInit.networks, atRootInit.layers, atRootInit.aliases = maps.Clone(networks), maps.Clone(layers), maps.Clone(aliases)
	// What protocols/local and protocols/command register, which the root's tests cannot import.
	RegisterNetwork("tcp", NetworkSpec{Plane: Stream, AddressKind: AddressHost, Network: testutils.System{}})
	RegisterNetwork("udp", NetworkSpec{Plane: Packet, AddressKind: AddressHost, Network: testutils.System{}})
	RegisterNetwork("unix", NetworkSpec{Plane: Stream, AddressKind: AddressPath, Network: testutils.System{}})
	RegisterNetwork("unixgram", NetworkSpec{Plane: Packet, AddressKind: AddressPath, Network: testutils.System{}})
	RegisterNetwork("cmd", NetworkSpec{Plane: Stream, AddressKind: AddressOpaque})
	RegisterLayer("dgram", dgram)
	RegisterNetwork("test-cmd", NetworkSpec{Plane: Stream, AddressKind: AddressOpaque})
	RegisterNetwork("fakenet", NetworkSpec{Plane: Stream, Network: &fakeNet{name: "impl"}})
	RegisterNetwork("test-lossy-net", NetworkSpec{Plane: Packet, Network: &lossyNet{fakeNet{name: "lossy"}, []string{"test-lossy-net"}}})
	RegisterLayer("test-tls", fakeAdapter("test-tls", Stream, Stream, "tls_skip_verify", "tls_self_signed", "tls_cert_file", "tls_key_file"))
	RegisterLayer("test-snappy", fakeAdapter("test-snappy", Stream, Stream))
	RegisterLayer("test-quic", fakeAdapter("test-quic", Packet, Stream))
	RegisterLayer("test-dtls", fakeAdapter("test-dtls", Packet, Packet))
	RegisterLayer("test-uot", fakeAdapter("test-uot", Stream, Packet))
	keep := fakeAdapter("test-keep", Stream, Stream)
	keep.Preserves = Packet
	RegisterLayer("test-keep", keep)
	// test-lossy is test-uot without datagram boundaries; test-lossy-keep is test-keep whose preserved datagrams lose them.
	lossy := fakeAdapter("test-lossy", Stream, Packet)
	lossy.Lossy = Packet
	RegisterLayer("test-lossy", lossy)
	lossyKeep := fakeAdapter("test-lossy-keep", Stream, Stream)
	lossyKeep.Preserves, lossyKeep.Lossy = Packet, Packet
	RegisterLayer("test-lossy-keep", lossyKeep)
	RegisterLayer("test-http", fakeProxy("test-http", Stream, Stream, 0, "username", "password"))
	RegisterLayer("test-socks4", fakeProxy("test-socks4", Stream, Stream, 0, "username", ""))
	RegisterLayer("test-ssh", fakeProxy("test-ssh", Stream, Stream, 0, "username", "password", "identity_file", "identity_data", "authorized_data"))
	RegisterLayer("test-socks5", fakeProxy("test-socks5", Stream, Stream|Packet, 0, "username", "password"))
	lossyProxy := fakeProxy("test-lossy-proxy", Stream, Stream|Packet, 0, "", "")
	lossyProxy.Lossy = Packet
	RegisterLayer("test-lossy-proxy", lossyProxy)
	RegisterLayer("test-ss", fakeProxy("test-ss", 0, 0, Stream|Packet, "username", "password"))
	anyProxy := fakeProxy("test-any", Stream, Stream, 0, "username", "password")
	anyProxy.NewClient, anyProxy.Networks = nil, nil
	RegisterLayer("test-any", anyProxy)
	// test-peer resolves the default peer of its udp dials and binds their sockets through local.
	RegisterLayer("test-peer", LayerSpec{Requires: Stream, Provides: Packet, Networks: []string{"udp"}, NewClient: func(Options) (*ClientFuncs, error) {
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
	RegisterLayer("test-kept", keepingAdapter("test-kept"))
	RegisterLayer("test-check-ss", checkingAdapter("test-check-ss", Stream, Stream, nil))
	RegisterLayer("test-check-sp", checkingAdapter("test-check-sp", Packet, Stream, nil))
	RegisterLayer("test-checkfail-ss", checkingAdapter("test-checkfail-ss", Stream, Stream, errCheck))
	RegisterLayer("test-checkfail-sp", checkingAdapter("test-checkfail-sp", Packet, Stream, errCheck))
	checkKeep := checkingAdapter("test-check-keep", Stream, Stream, nil)
	checkKeep.Preserves = Packet
	RegisterLayer("test-check-keep", checkKeep)
	checkKeepStream := checkingAdapter("test-check-keep-stream", Packet, Packet, nil)
	checkKeepStream.Preserves = Stream
	RegisterLayer("test-check-keep-stream", checkKeepStream)
	RegisterLayer("closable", declared(Stream, Stream, &AdapterFuncs{Stream: &Link{}, Close: func() error { record("closable.close"); return nil }}, nil))
	RegisterLayer("closableproxy", declaredProxy(Stream, 0, &ClientFuncs{Dial: failDial, Close: func() error { record("closableproxy.close"); return nil }}, nil))
	RegisterLayer("closableserver", declaredServer(Stream, 0, &ServerFuncs{Serve: failServe, Close: func() error { record("closableserver.close"); return nil }}, nil))
	RegisterLayer("nilproxy", LayerSpec{
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
	RegisterLayer("test-reject-client-packet", declaredProxy(Packet, 0, &ClientFuncs{Close: func() error { record("test-reject-client-packet.close"); return nil }}, nil))
	RegisterLayer("test-reject-server-packet", declaredServer(Stream, Packet, &ServerFuncs{Serve: failServe, Close: func() error { record("test-reject-server-packet.close"); return nil }}, nil))
	// test-counted passes its carrier through and records its Close.
	RegisterLayer("test-counted", LayerSpec{Preserves: Stream | Packet, NewAdapter: func(Options) (*AdapterFuncs, error) {
		return &AdapterFuncs{Close: func() error { record("test-counted.close"); return nil }}, nil
	}})
	// test-packet-server binds only a Packet carrier, so a Stream one leaves it nothing to serve.
	RegisterLayer("test-packet-server", LayerSpec{Provides: Stream, Preserves: Packet, NewServer: func(Options) (*ServerFuncs, error) {
		record("test-packet-server.newserver")
		return &ServerFuncs{ServePacket: func(_ context.Context, _ net.PacketConn, upstream Network) error {
			record("test-packet-server.servepacket upstream=%s", netName(upstream))
			return nil
		}}, nil
	}})
	// test-relay's server binds through its upstream on the network its relay option names, a socket on a datagram one, returning the outcome.
	RegisterLayer("test-relay", LayerSpec{Requires: Stream, Provides: Stream, OptionKeys: []string{"relay"}, NewServer: func(opts Options) (*ServerFuncs, error) {
		return &ServerFuncs{Serve: func(ctx context.Context, _ net.Listener, upstream Network) error {
			network := opts["relay"]
			var bound io.Closer
			var err error
			if _, plane, _ := lookupBase(network); plane == Packet {
				bound, err = upstream.ListenPacket(ctx, network, "127.0.0.1:0")
			} else {
				bound, err = upstream.Listen(ctx, network, "127.0.0.1:0")
			}
			if err != nil {
				return err
			}
			return bound.Close()
		}}, nil
	}})
	RegisterAlias("test-https", "test-http+test-tls")
	RegisterAlias("later", "pending+test-tls")
}

var registered int

// fresh numbers name anew on each call, so a test registering it passes when run again in one process.
func fresh(name string) string {
	registered++
	return fmt.Sprintf("%s-%d", name, registered)
}

func mk(network string, schemes ...string) Chain {
	c := Chain{Endpoint: Endpoint{Network: network, Address: "127.0.0.1:1"}}
	for _, s := range schemes {
		c.Layers = append(c.Layers, Layer{Scheme: s})
	}
	return c
}

// dgram is protocols/command's layer of that name, declared alike.
var dgram = LayerSpec{
	Requires: Stream,
	Provides: Packet,
	Lossy:    Packet,
	NewAdapter: func(Options) (*AdapterFuncs, error) {
		return &AdapterFuncs{Packet: &Link{Over: Stream, Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
			c, err := carrier(ctx)
			if err != nil {
				return nil, err
			}
			return netutils.StreamPacket(c, c.RemoteAddr()), nil
		}}}, nil
	},
}
