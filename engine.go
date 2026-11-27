package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// TransportEngine builds adapter chains into transports, borrowing Base without ever closing it.
type TransportEngine struct {
	Base Network // reaches the endpoint; nil resolves each call by network name: the registered implementation, else ErrUnsupported
}

// ClientEngine builds proxy chains into clients, borrowing Base and Local without ever closing them.
type ClientEngine struct {
	Base  Network // reaches the endpoint; nil resolves each call as a nil TransportEngine.Base does
	Local Network // what clients bind their own sockets through; nil resolves each call as a nil Base does
}

// ServerEngine builds proxy chains into servers, borrowing Base and Upstream without ever closing them.
type ServerEngine struct {
	Base     Network // reaches the endpoint; nil resolves each call as a nil TransportEngine.Base does
	Upstream Network // what servers reach their targets through; nil resolves each call as a nil Base does
}

// build stacks r's layers from the innermost out to from over base.
func build(base Network, r *resolved, from int) (Transport, error) {
	n, layered := orByName(base), len(r.layers) > 0
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
	n, err := r.specs[0].client(inner, borrowed{orByName(e.Local)}, c.Layers[0].Options.clone(), r.planes[0])
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
	s, err := spec.server(inner, borrowed{orByName(e.Upstream)}, c.Layers[0].Options.clone())
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

// byName is the Network an engine's nil Base, Local or Upstream stands for, resolving each call by its network name.
type byName struct{}

// resolve is the registered implementation of network's base, else a Network refusing every call.
func (byName) resolve(network string) Network {
	base, _, _ := lookupBase(network)
	if ns, _ := lookupNetwork(base); ns.Network != nil {
		return ns.Network
	}
	return NetworkFuncs{}
}

func (n byName) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.resolve(network).DialContext(ctx, network, address)
}

func (n byName) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return n.resolve(network).Listen(ctx, network, address)
}

func (n byName) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return n.resolve(network).ListenPacket(ctx, network, address)
}

// Lossy forwards what network's resolved implementation reports.
func (n byName) Lossy(network string) bool {
	return isLossy(n.resolve(network), network)
}

func orByName(n Network) Network {
	if n != nil {
		return n
	}
	return byName{}
}

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
