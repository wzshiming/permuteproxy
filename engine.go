package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// TransportEngine builds adapter chains into transports, borrowing Base without ever closing it.
type TransportEngine struct {
	Base Network // reaches the endpoint; nil is DefaultNetwork
}

// ClientEngine builds proxy chains into clients, borrowing Base and Local without ever closing them.
type ClientEngine struct {
	Base  Network // reaches the endpoint; nil is DefaultNetwork
	Local Network // what clients bind their own sockets through; nil is DefaultNetwork
}

// ServerEngine builds proxy chains into servers, borrowing Base and Upstream without ever closing them.
type ServerEngine struct {
	Base     Network // reaches the endpoint; nil is DefaultNetwork
	Upstream Network // what servers reach their targets through; nil is DefaultNetwork
}

// build stacks r's layers from the innermost out to from over base.
func build(base Network, r *resolved, from int) (Transport, error) {
	n, layered := orDefault(base), len(r.layers) > 0
	dial := bind(n, r.stream, r.packet, r.dial, layered)
	// The layers get what the carrier offers once a lossy network took its datagrams, not what resolve assumed.
	r.offer(dial.Planes())
	var t Transport = dial
	if r.listen != r.dial {
		t = split(t, bind(n, r.stream, r.packet, r.listen, layered))
	}
	t, err := r.stack(t, r.own, len(r.layers))
	if err != nil {
		return nil, err
	}
	if a := r.around; a != nil {
		// The split admits only the plane the expression provides, so the declared name serves either.
		t = split(t, bind(n, a.Network, a.Network, a.Address, r.own > 0))
	}
	return r.stack(t, from, r.own)
}

// Transport builds an adapter chain; with layers, the result's Close forwards to the outermost layer's own result.
func (e TransportEngine) Transport(c Chain) (Transport, error) {
	r, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if len(r.specs) > 0 && r.specs[0].isProxy() {
		return nil, fmt.Errorf("layer %q: proxy needs a ClientEngine or ServerEngine: %w", c.Layers[0].Scheme, ErrInvalidChain)
	}
	return build(e.Base, r, 0)
}

// below builds over base the Transport under c's outermost layer, which must be a proxy declaring side.
func below(base Network, c Chain, side string, declares func(LayerSpec) bool) (*resolved, Transport, error) {
	r, err := c.proxy()
	if err != nil {
		return nil, nil, err
	}
	if !declares(r.specs[0]) {
		return nil, nil, fmt.Errorf("layer %q: %s: %w", c.Layers[0].Scheme, side, ErrUnsupported)
	}
	inner, err := build(base, r, 1)
	if err != nil {
		return nil, nil, err
	}
	return r, inner, nil
}

// Client builds the client of a proxy chain's outermost layer, which binds its own sockets through Local; the result's Close forwards to the layer's own result. A chain of one network that declares NetworkSpec.NewClient, as cmd:ssh -W %h:%p jump and nc:ssh jump are, is the client that network builds over Base.
func (e ClientEngine) Client(c Chain) (Network, error) {
	if c.selfClient() {
		return e.network(c)
	}
	r, inner, err := below(e.Base, c, "client", func(s LayerSpec) bool { return s.NewClient != nil })
	if err != nil {
		return nil, err
	}
	n, err := r.specs[0].client(inner, borrowed{orDefault(e.Local)}, c.Layers[0].Options.clone(), r.planes[0])
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", c.Layers[0].Scheme, err)
	}
	return n, nil
}

// Server builds the server of a proxy chain's outermost layer, which reaches its targets through Upstream.
func (e ServerEngine) Server(c Chain) (Server, error) {
	r, inner, err := below(e.Base, c, "server", func(s LayerSpec) bool { return s.NewServer != nil })
	if err != nil {
		return nil, err
	}
	scheme, spec := c.Layers[0].Scheme, r.specs[0]
	if p := inner.Planes(); p&(spec.Requires|spec.Preserves) == 0 || p&spec.Requires != spec.Requires {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: serve over %v: %w", scheme, p, ErrUnsupported)
	}
	s, err := spec.server(inner, borrowed{orDefault(e.Upstream)}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	return s, nil
}

// NewClient builds the client of the proxy chain uri names, such as socks5://user:pass@127.0.0.1:1080 or cmd:ssh -W %h:%p jump, as a zero ClientEngine does.
func NewClient(uri string) (Network, error) {
	c, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return ClientEngine{}.Client(c)
}

// NewServer builds the server of the proxy chain uri names, such as socks5://user:pass@:1080, as a zero ServerEngine does; its Run binds and serves.
func NewServer(uri string) (Server, error) {
	c, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return ServerEngine{}.Server(c)
}

// ListenAndServe serves the proxy chain uri names until serving fails or ctx ends, returning nil for the latter.
func ListenAndServe(ctx context.Context, uri string) error {
	s, err := NewServer(uri)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Run(ctx)
}

// borrowed forwards only Network and Lossy of an injected base, never its Close.
type borrowed struct{ Network }

// Lossy forwards what the borrowed network reports.
func (b borrowed) Lossy(network string) bool {
	return isLossy(b.Network, network)
}

// DefaultNetwork resolves each call by its network name to what is registered under it: the
// network's implementation or, for a network declared by expression, as cmd-nc is, that
// expression built for the call. It refuses any other name with ErrUnsupported. An engine's
// nil Base, Local or Upstream stands for it, and it is the base to wrap for a caller that
// reaches some names another way.
var DefaultNetwork Network = defaultNetwork{}

// defaultNetwork is the type of DefaultNetwork; it holds nothing, as each call looks its network up in the registry.
type defaultNetwork struct{}

// resolve is the registered spec of network's base and its implementation, else a Network refusing every call.
func (defaultNetwork) resolve(network string) (string, NetworkSpec, Network) {
	base, _, _ := lookupBase(network)
	ns, _ := lookupNetwork(base)
	if ns.Network != nil {
		return base, ns, ns.Network
	}
	return base, ns, NetworkFuncs{}
}

func (n defaultNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	base, ns, impl := n.resolve(network)
	if ns.Dial == "" {
		return impl.DialContext(ctx, network, address)
	}
	return dialOnce(ctx, n, Chain{Endpoint: Endpoint{Network: base, Address: address}}, ns.Plane)
}

// Listen goes to the implementation unless the network declares a Listen expression, as a chain's own listening does.
func (n defaultNetwork) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	base, ns, impl := n.resolve(network)
	if ns.Listen == "" {
		return impl.Listen(ctx, network, address)
	}
	t, err := TransportEngine{Base: n}.Transport(Chain{Endpoint: Endpoint{Network: base, Address: address}})
	if err != nil {
		return nil, err
	}
	ln, err := t.Listen(ctx)
	if err != nil {
		closeIf(t)
		return nil, err
	}
	return listenerCloser{ln, closeBoth(ln, t)}, nil
}

func (n defaultNetwork) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	base, ns, impl := n.resolve(network)
	if ns.Listen == "" {
		return impl.ListenPacket(ctx, network, address)
	}
	t, err := TransportEngine{Base: n}.Transport(Chain{Endpoint: Endpoint{Network: base, Address: address}})
	if err != nil {
		return nil, err
	}
	pc, err := t.ListenPacket(ctx)
	if err != nil {
		closeIf(t)
		return nil, err
	}
	return packetCloser{pc, closeBoth(pc, t)}, nil
}

// Lossy forwards what network's implementation reports, and reports a network whose Dial expression loses datagram boundaries.
func (n defaultNetwork) Lossy(network string) bool {
	_, ns, impl := n.resolve(network)
	if ns.Dial != "" {
		// RegisterNetwork has checked the expression.
		x, _ := parseExpression(ns.Dial)
		if _, lossy, _ := x.offers(); lossy&ns.Plane != 0 {
			return true
		}
	}
	return isLossy(impl, network)
}

func orDefault(n Network) Network {
	if n != nil {
		return n
	}
	return DefaultNetwork
}

// dialOnce builds c's adapter chain over base for one dial on plane; the conn's Close releases what was built.
func dialOnce(ctx context.Context, base Network, c Chain, plane Plane) (net.Conn, error) {
	t, err := TransportEngine{Base: base}.Transport(c)
	if err != nil {
		return nil, err
	}
	conn, err := t.Dial(ctx, plane)
	if err != nil {
		closeIf(t)
		return nil, err
	}
	if _, ok := t.(io.Closer); !ok {
		return conn, nil
	}
	if pc, ok := conn.(net.PacketConn); ok {
		return netutils.ConnWithProcess(packetConnCloser{conn, pc, closeBoth(conn, t)}, conn), nil
	}
	return netutils.ConnWithCloser(conn, closeBoth(conn, t)), nil
}

// closeBoth closes c and then what t owns, both once.
func closeBoth(c io.Closer, t Transport) func() error {
	return sync.OnceValue(func() error { return errors.Join(c.Close(), closeIf(t)) })
}

type listenerCloser struct {
	net.Listener
	close func() error
}

func (l listenerCloser) Close() error { return l.close() }

type packetCloser struct {
	net.PacketConn
	close func() error
}

func (p packetCloser) Close() error { return p.close() }

// packetConnCloser keeps a dialed datagram conn a net.PacketConn.
type packetConnCloser struct {
	net.Conn
	packet net.PacketConn
	close  func() error
}

func (p packetConnCloser) ReadFrom(b []byte) (int, net.Addr, error) { return p.packet.ReadFrom(b) }

func (p packetConnCloser) WriteTo(b []byte, addr net.Addr) (int, error) {
	return p.packet.WriteTo(b, addr)
}

func (p packetConnCloser) Close() error { return p.close() }

// assembled is a Transport of functions that owns what close releases.
type assembled struct {
	TransportFuncs
	close func() error
}

// Close releases what the Transport owns.
func (a assembled) Close() error {
	return a.close()
}

// split dials through dial and listens through listen, both on dial's planes; Close reaches dial.
func split(dial, listen Transport) Transport {
	return assembled{TransportFuncs{Plane: dial.Planes(), DialFunc: dial.Dial, ListenFunc: listen.Listen, ListenPacketFunc: listen.ListenPacket}, func() error { return closeIf(dial) }}
}

// bound binds a Network to one endpoint; stream/packet hold the network names per plane.
type bound struct {
	network Network
	stream  string
	packet  string
	address string
}

func (b *bound) Planes() Plane {
	var p Plane
	if b.stream != "" {
		p |= Stream
	}
	if b.packet != "" {
		p |= Packet
	}
	return p
}

func (b *bound) Dial(ctx context.Context, plane Plane) (net.Conn, error) {
	switch {
	case plane == Stream && b.stream != "":
		return b.network.DialContext(ctx, b.stream, b.address)
	case plane == Packet && b.packet != "":
		return netutils.DialPacket(ctx, b.packet, b.address, b.network.ListenPacket)
	}
	return nil, fmt.Errorf("dial %v on %s: %w", plane, b.address, ErrUnsupported)
}

func (b *bound) Listen(ctx context.Context) (net.Listener, error) {
	if b.stream == "" {
		return nil, fmt.Errorf("listen on %s: %w", b.address, ErrUnsupported)
	}
	return b.network.Listen(ctx, b.stream, b.address)
}

func (b *bound) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if b.packet == "" {
		return nil, fmt.Errorf("listen packet on %s: %w", b.address, ErrUnsupported)
	}
	return b.network.ListenPacket(ctx, b.packet, b.address)
}

// bind binds n to address on the networks named per plane, layered when layers sit above it.
func bind(n Network, stream, packet, address string, layered bool) *bound {
	b := &bound{network: n, stream: stream, packet: packet, address: address}
	// A layer is never offered a datagram plane that its network reports lossy.
	if layered && b.packet != "" && isLossy(b.network, b.packet) {
		b.packet = ""
	}
	return b
}

// stack builds layers hi-1 out to lo over t, closing what it holds when a layer fails.
func (r *resolved) stack(t Transport, lo, hi int) (Transport, error) {
	for i := hi - 1; i >= lo; i-- {
		next, err := r.specs[i].adapt(t, r.options(i), r.planes[i])
		if err != nil {
			closeIf(t)
			return nil, fmt.Errorf("layer %q: %w", r.layers[i].Scheme, err)
		}
		t = next
	}
	return t, nil
}

// closeOnce calls release, when set, and then closes inner, both at most once.
func closeOnce(release func() error, inner Transport) func() error {
	return sync.OnceValue(func() error {
		var err error
		if release != nil {
			err = release()
		}
		return errors.Join(err, closeIf(inner))
	})
}

// reject calls release, when set, for a declaration the root package refuses, and marks err as an invalid chain unless it is one.
func reject(release func() error, err error) error {
	if release != nil {
		release()
	}
	if errors.Is(err, ErrInvalidChain) {
		return err
	}
	return invalid(err)
}

func invalid(err error) error {
	return fmt.Errorf("%w: %w", err, ErrInvalidChain)
}
