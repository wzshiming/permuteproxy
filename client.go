package permuteproxy

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// ClientFuncs declares a proxy's client over the networks LayerSpec.Networks lists or Derive expresses, its functions receiving one inner Transport for the client's life.
type ClientFuncs struct {
	Dial         func(ctx context.Context, inner Transport, network, address string) (net.Conn, error)                      // a conn to address on a stream network
	Listen       func(ctx context.Context, inner Transport, network, address string) (net.Listener, error)                  // optional; a listener at address on the proxy's side of a stream network, as BIND and a remote forward open
	ListenPacket func(ctx context.Context, inner Transport, local Network, network, address string) (net.PacketConn, error) // a socket reaching any peer, its own end bound at address through local
	Peer         func(ctx context.Context, network, address string) (net.Addr, error)                                       // optional; a udp dial's default peer, else its address carried unresolved
	Derive       map[string]string                                                                                          // optional; base network -> expression over its own networks; Dial's conns must unblock a pending Read on Close
	Close        func() error                                                                                               // optional; releases what NewClient acquired
}

// client builds over inner the client s.NewClient declares, binding its own end through local and admitting only networks on plane, what the chain exposes.
func (s LayerSpec) client(inner Transport, local Network, opts Options, plane Plane) (Network, error) {
	funcs, err := s.NewClient(opts)
	switch {
	case err != nil:
		return nil, invalid(err)
	case funcs == nil:
		return nil, fmt.Errorf("NewClient returned nil: %w", ErrInvalidChain)
	}
	derived, err := s.derive(funcs.Derive)
	if err != nil {
		return nil, reject(funcs.Close, err)
	}
	var derivedPlanes, overPlanes Plane
	for _, d := range derived {
		derivedPlanes |= d.plane
		over, _ := lookupNetwork(d.x.network)
		overPlanes |= over.Plane
	}
	switch {
	case funcs.Dial == nil && (s.Provides|s.Preserves|overPlanes)&Stream != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no Dial for %v", Stream))
	case funcs.ListenPacket == nil && derivedPlanes&Packet == 0 && (s.Provides|s.Preserves)&Packet != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no ListenPacket or derived datagram network for %v", Packet))
	case funcs.ListenPacket == nil && overPlanes&Packet != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no ListenPacket for a derivation over %v", Packet))
	}
	a := &assembledNetwork{close: closeOnce(funcs.Close, inner), spec: s, plane: plane, derived: derived}
	a.NetworkFuncs = NetworkFuncs{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			base, plane := a.admit(network)
			d, ok := derived[base]
			switch {
			case ok:
				return d.dialContext(ctx, a, address)
			case plane == Stream:
				return funcs.Dial(ctx, inner, network, address)
			case base == "udp" && funcs.ListenPacket != nil && !isLossy(local, network):
				return funcs.dialUDP(ctx, inner, local, network, address)
			}
			return nil, fmt.Errorf("dial %s: %w", network, ErrUnsupported)
		},
		ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
			base, plane := a.admit(network)
			// A derived network is dialed through an expression, which has no remote end to listen at.
			if _, ok := derived[base]; ok || plane != Stream || funcs.Listen == nil {
				return nil, fmt.Errorf("listen %s: %w", network, ErrUnsupported)
			}
			return funcs.Listen(ctx, inner, network, address)
		},
		ListenPacketFunc: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			base, plane := a.admit(network)
			d, ok := derived[base]
			switch {
			case plane == Packet && ok:
				return d.listenPacket(a, address)
			case plane == Packet && funcs.ListenPacket != nil && !isLossy(local, network):
				return funcs.ListenPacket(ctx, inner, local, network, address)
			}
			return nil, fmt.Errorf("listen packet %s: %w", network, ErrUnsupported)
		},
	}
	return a, nil
}

// assembledNetwork is a declared client's Network; the engine built its inner Transport, so Close releases it too.
type assembledNetwork struct {
	NetworkFuncs
	close   func() error
	mu      sync.RWMutex // a derived dial checks closed and joins dials under it for reading
	closed  bool
	dials   sync.WaitGroup // derived dials in flight
	spec    LayerSpec
	plane   Plane // what the chain exposes; a network on another plane is refused before it reaches the client
	derived map[string]derivation
}

// Close refuses derived dials, releases the client once, which may end those in flight, and then waits for them.
func (a *assembledNetwork) Close() error {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	err := a.close()
	a.dials.Wait()
	return err
}

// Lossy reports the networks its client admits on a plane its layer declares Lossy, and those it derives through a lossy expression.
func (a *assembledNetwork) Lossy(network string) bool {
	base, plane := a.admit(network)
	return plane&a.spec.Lossy != 0 || a.derived[base].lossy
}

// admit maps a network its client lists or derives on a plane the chain exposes to its base name and plane, and any other network to no plane.
func (a *assembledNetwork) admit(network string) (string, Plane) {
	base, plane, _ := lookupBase(network)
	if _, derived := a.derived[base]; plane&a.plane == 0 || !derived && !slices.Contains(a.spec.Networks, base) {
		return "", 0
	}
	return base, plane
}

// dialUDP binds a socket at ":0" through f.ListenPacket, as a conn whose Write reaches the default peer.
func (f *ClientFuncs) dialUDP(ctx context.Context, inner Transport, local Network, network, address string) (net.Conn, error) {
	peer := netutils.NewNetAddr("udp", address)
	if f.Peer != nil {
		var err error
		if peer, err = f.Peer(ctx, network, address); err != nil {
			return nil, err
		}
	}
	// The socket faces the proxy's relay, so the target's family must not constrain it.
	pc, err := f.ListenPacket(ctx, inner, local, "udp", ":0")
	if err != nil {
		return nil, err
	}
	return netutils.WrapPacket(pc, peer), nil
}

// selfClient reports whether c is one network that declares its own client, such as nc:ssh jump.
func (c Chain) selfClient() bool {
	ns, _ := lookupNetwork(c.Endpoint.Network)
	return len(c.Layers) == 0 && ns.NewClient != nil
}

// network builds the client the network of a selfClient chain declares, over Base.
func (e ClientEngine) network(c Chain) (Network, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ns, _ := lookupNetwork(c.Endpoint.Network)
	n, err := ns.NewClient(borrowed{orDefault(e.Base)}, c.Endpoint.Address)
	switch {
	case err != nil:
		return nil, fmt.Errorf("network %q: %w", c.Endpoint.Network, reject(nil, err))
	case n == nil:
		return nil, fmt.Errorf("network %q: NewClient returned nil: %w", c.Endpoint.Network, ErrInvalidChain)
	}
	return n, nil
}

// derivable are the base networks a client may derive, those the root package declares but unixgram, whose local end is a path.
var derivable = []string{"tcp", "udp", "unix", "cmd"}

// derivation is a base network a client derives by expression from the networks it lists.
type derivation struct {
	network string
	kind    AddressKind
	plane   Plane
	lossy   bool // its expression loses datagram boundaries, as through dgram
	x       expression
}

// derive checks each network exprs derives for a client of s.
func (s LayerSpec) derive(exprs map[string]string) (map[string]derivation, error) {
	derived := map[string]derivation{}
	for _, network := range slices.Sorted(maps.Keys(exprs)) {
		switch {
		case !slices.Contains(derivable, network):
			return nil, fmt.Errorf("network %q in Derive: not one of the base networks %q", network, derivable)
		case slices.Contains(s.Networks, network):
			return nil, fmt.Errorf("network %q in Derive: also listed in Networks", network)
		}
		ns, _ := lookupNetwork(network)
		x, err := checkExpression(exprs[network], ns.AddressKind)
		if err != nil {
			return nil, fmt.Errorf("network %q in Derive: %w", network, err)
		}
		if !slices.Contains(s.Networks, x.network) {
			return nil, fmt.Errorf("network %q in Derive: %q is not listed in Networks", network, x.network)
		}
		planes, lossy, err := x.offers()
		switch {
		case err != nil:
			return nil, fmt.Errorf("network %q in Derive: %w", network, err)
		case planes&ns.Plane == 0:
			return nil, fmt.Errorf("network %q in Derive: the expression offers %v, not %v", network, planes, ns.Plane)
		}
		derived[network] = derivation{network: network, kind: ns.AddressKind, plane: ns.Plane, lossy: lossy&ns.Plane != 0, x: x}
	}
	return derived, nil
}

// dialContext dials a derived stream network at once, a derived datagram network on the first Write to address.
func (d derivation) dialContext(ctx context.Context, a *assembledNetwork, address string) (net.Conn, error) {
	if d.plane == Stream {
		return d.dial(ctx, a, address)
	}
	if _, err := d.x.expand(d.kind, address); err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", d.network, address, err)
	}
	pc, err := d.sessions(a)
	if err != nil {
		return nil, err
	}
	return netutils.WrapPacket(pc, netutils.NewNetAddr(d.network, address)), nil
}

// listenPacket binds a derived datagram network, which has no local end of its own to bind at a chosen address.
func (d derivation) listenPacket(a *assembledNetwork, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "0" || host != "" && !net.ParseIP(host).IsUnspecified() {
		return nil, fmt.Errorf("listen packet %s %s: binds only an unspecified host with port 0: %w", d.network, address, ErrUnsupported)
	}
	return d.sessions(a)
}

// sessions reaches each peer over a dial of its own.
func (d derivation) sessions(a *assembledNetwork) (net.PacketConn, error) {
	a.mu.RLock()
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return nil, fmt.Errorf("%s: %w", d.network, net.ErrClosed)
	}
	return netutils.NewSessions(func(ctx context.Context, peer net.Addr) (net.Conn, error) {
		return d.dial(ctx, a, peer.String())
	}, netutils.SessionOptions{}), nil
}

// dial builds d's expression for address over a and dials the derived plane; the conn's Close releases what it built.
func (d derivation) dial(ctx context.Context, a *assembledNetwork, address string) (net.Conn, error) {
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return nil, fmt.Errorf("dial %s %s: %w", d.network, address, net.ErrClosed)
	}
	a.dials.Add(1)
	a.mu.RUnlock()
	defer a.dials.Done()
	text, err := d.x.expand(d.kind, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", d.network, address, err)
	}
	return dialOnce(ctx, a, d.x.over(text), d.plane)
}
