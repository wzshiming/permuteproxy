package permuteproxy

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// ClientFuncs declares a proxy's client over the networks LayerSpec.Networks lists or Derive expresses, its functions receiving one inner Transport for the client's life.
type ClientFuncs struct {
	Dial         func(ctx context.Context, inner Transport, network, address string) (net.Conn, error)                      // a conn to address on a stream network
	ListenPacket func(ctx context.Context, inner Transport, local Network, network, address string) (net.PacketConn, error) // a socket reaching any peer, its own end bound at address through local
	Peer         func(ctx context.Context, network, address string) (net.Addr, error)                                       // optional; a udp dial's default peer, else its address carried unresolved
	Derive       map[string]string                                                                                          // optional; base network -> expression over its own networks; Dial's conns must unblock a pending Read on Close
	Close        func() error                                                                                               // optional; releases what NewClient acquired
}

// client builds over inner the client s.NewClient declares, binding its own end through local.
func (s LayerSpec) client(inner Transport, local Network, opts Options) (Network, error) {
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
	a := &assembledNetwork{close: closeOnce(funcs.Close, inner), spec: s, derived: derived}
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

// admit maps a network its client lists or derives to its base name and plane, and any other network to no plane.
func (a *assembledNetwork) admit(network string) (string, Plane) {
	base, plane, _ := lookupBase(network)
	if _, derived := a.derived[base]; !derived && !slices.Contains(a.spec.Networks, base) {
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
