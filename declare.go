package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/serverutils"
)

// AdapterFuncs declares an adapter per plane; a preserved plane without a Link passes through unchanged.
type AdapterFuncs struct {
	Stream       *Link        // how the layer provides Stream
	Packet       *Link        // how the layer provides Packet
	BeforeDial   func() error // optional; runs before a Dial obtains a link's carrier, failing the Dial with its error
	BeforeListen func() error // optional; runs before a Listen or ListenPacket obtains a link's carrier, failing it with its error
	Close        func() error // optional; releases what NewAdapter acquired
}

// Link derives one plane from a carrier of one plane, through a client and a server form.
// Each function owns the carrier it is handed, also when it fails.
type Link struct {
	Over           Plane                                                         // carrier plane consumed; zero means the provided plane itself
	Client         func(ctx context.Context, carrier net.Conn) (net.Conn, error) // a Packet carrier is also a net.PacketConn with a default peer
	Listener       func(ln net.Listener) (net.Listener, error)                   // Stream over a Stream carrier
	PacketListener func(pc net.PacketConn) (net.Listener, error)                 // Stream over a Packet carrier
	PacketConn     func(pc net.PacketConn) (net.PacketConn, error)               // Packet over a Packet carrier
}

// carrier is the plane l consumes to provide plane p.
func (l *Link) carrier(p Plane) Plane {
	if l.Over == 0 {
		return p
	}
	return l.Over
}

// link is how f provides plane p.
func (f *AdapterFuncs) link(p Plane) *Link {
	if p == Packet {
		return f.Packet
	}
	return f.Stream
}

// fits reports whether each server form l sets is the one for p over a carrier of plane over.
func (l *Link) fits(p, over Plane) bool {
	return (l.Listener == nil || p == Stream && over == Stream) &&
		(l.PacketListener == nil || p == Stream && over == Packet) &&
		(l.PacketConn == nil || p == Packet && over == Packet)
}

// covers reports how funcs falls short of the planes s declares.
func (s Spec) covers(funcs *AdapterFuncs) error {
	for _, p := range []Plane{Stream, Packet} {
		link := funcs.link(p)
		if link == nil {
			if s.Provides&p != 0 {
				return fmt.Errorf("no link provides %v", p)
			}
			continue
		}
		over := link.carrier(p)
		switch {
		case (s.Provides|s.Preserves)&p == 0:
			return fmt.Errorf("%v link on a plane the layer neither provides nor preserves", p)
		case over != Stream && over != Packet, (s.Requires|s.Preserves)&over == 0:
			return fmt.Errorf("%v link over %v, not one plane the layer requires or preserves", p, over)
		case !link.fits(p, over):
			return fmt.Errorf("%v link over %v sets the server form of another pair", p, over)
		}
	}
	return nil
}

// adapt is the Adapt that RegisterLayer derives from s.NewAdapter.
func (s Spec) adapt(inner Transport, opts Options) (Transport, error) {
	funcs, err := s.NewAdapter(opts)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %w", err, ErrInvalidChain)
	case funcs == nil:
		return nil, fmt.Errorf("NewAdapter returned nil: %w", ErrInvalidChain)
	}
	if err := s.covers(funcs); err != nil {
		return nil, reject(funcs.Close, err)
	}
	t := TransportFuncs{Plane: s.Provides | (inner.Planes() & s.Preserves)}
	t.DialFunc = func(ctx context.Context, plane Plane) (net.Conn, error) {
		link := funcs.link(plane)
		switch {
		case link == nil:
			return inner.Dial(ctx, plane)
		case link.Client == nil:
			return nil, fmt.Errorf("dial %v: %w", plane, ErrUnsupported)
		}
		dial := func(ctx context.Context) (net.Conn, error) { return inner.Dial(ctx, link.carrier(plane)) }
		return apply(ctx, funcs.BeforeDial, dial, func(conn net.Conn) (net.Conn, error) { return link.Client(ctx, conn) })
	}
	// covers admits a server form only for its own pair, so the one set picks the carrier.
	switch link := funcs.Stream; {
	case link == nil:
		t.ListenFunc = inner.Listen
	case link.Listener != nil:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) {
			return apply(ctx, funcs.BeforeListen, inner.Listen, link.Listener)
		}
	case link.PacketListener != nil:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) {
			return apply(ctx, funcs.BeforeListen, inner.ListenPacket, link.PacketListener)
		}
	}
	switch link := funcs.Packet; {
	case link == nil:
		t.ListenPacketFunc = inner.ListenPacket
	case link.PacketConn != nil:
		t.ListenPacketFunc = func(ctx context.Context) (net.PacketConn, error) {
			return apply(ctx, funcs.BeforeListen, inner.ListenPacket, link.PacketConn)
		}
	}
	return assembled{t, closeOnce(funcs.Close, inner)}, nil
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

// reject calls release, when set, for a declaration the root package refuses, and marks err as an invalid chain.
func reject(release func() error, err error) error {
	if release != nil {
		release()
	}
	return fmt.Errorf("%w: %w", err, ErrInvalidChain)
}

// assembled is a declared layer's Transport; adapter code never sees inner, so Close releases it too.
type assembled struct {
	TransportFuncs
	close func() error
}

// Close releases the layer and then its inner Transport, once.
func (a assembled) Close() error {
	return a.close()
}

// apply runs before, when set, then hands the carrier obtain gets to f, which owns it from then on.
func apply[C, R any](ctx context.Context, before func() error, obtain func(context.Context) (C, error), f func(C) (R, error)) (r R, _ error) {
	if before != nil {
		if err := before(); err != nil {
			return r, err
		}
	}
	carrier, err := obtain(ctx)
	if err != nil {
		return r, err
	}
	return f(carrier)
}

// ClientFuncs declares a proxy's client; the root package admits the networks Spec.Networks lists and derives udp dials.
// Its functions receive the same inner Transport on every call for the life of the client.
type ClientFuncs struct {
	Dial         func(ctx context.Context, inner Transport, network, address string) (net.Conn, error)                      // a conn to address on a stream network
	ListenPacket func(ctx context.Context, inner Transport, local Network, network, address string) (net.PacketConn, error) // a socket reaching any peer, its own end bound at address through local
	Peer         func(ctx context.Context, network, address string) (net.Addr, error)                                       // optional; a udp dial's default peer, else its address carried unresolved
	Close        func() error                                                                                               // optional; releases what NewClient acquired
}

// client is the Client that RegisterLayer derives from s.NewClient.
func (s Spec) client(inner Transport, local Network, opts Options) (Network, error) {
	funcs, err := s.NewClient(opts)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %w", err, ErrInvalidChain)
	case funcs == nil:
		return nil, fmt.Errorf("NewClient returned nil: %w", ErrInvalidChain)
	case funcs.Dial == nil && (s.Provides|s.Preserves)&Stream != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no Dial for %v", Stream))
	case funcs.ListenPacket == nil && (s.Provides|s.Preserves)&Packet != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no ListenPacket for %v", Packet))
	}
	n := NetworkFuncs{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			switch base, plane := s.admit(network); {
			case plane == Stream:
				return funcs.Dial(ctx, inner, network, address)
			case base == "udp" && !isLossy(local, network):
				return funcs.dialUDP(ctx, inner, local, network, address)
			}
			return nil, fmt.Errorf("dial %s: %w", network, ErrUnsupported)
		},
		ListenPacketFunc: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			if _, plane := s.admit(network); plane != Packet || isLossy(local, network) {
				return nil, fmt.Errorf("listen packet %s: %w", network, ErrUnsupported)
			}
			return funcs.ListenPacket(ctx, inner, local, network, address)
		},
	}
	return assembledNetwork{n, closeOnce(funcs.Close, inner), s}, nil
}

// assembledNetwork is a declared client's Network; the engine built its inner Transport, so Close releases it too.
type assembledNetwork struct {
	NetworkFuncs
	close func() error
	spec  Spec
}

// Close releases the client and then its inner Transport, once.
func (a assembledNetwork) Close() error {
	return a.close()
}

// Lossy reports the networks its layer admits on a plane the layer declares Lossy.
func (a assembledNetwork) Lossy(network string) bool {
	_, plane := a.spec.admit(network)
	return plane&a.spec.Lossy != 0
}

// admit maps a network s lists to its base name and plane, and any other network to no plane.
func (s Spec) admit(network string) (string, Plane) {
	base, plane, _ := lookupBase(network)
	if !slices.Contains(s.Networks, base) {
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
	pc, err := f.ListenPacket(ctx, inner, local, network, ":0")
	if err != nil {
		return nil, err
	}
	return netutils.WrapPacket(pc, peer), nil
}

// ServerFuncs declares a proxy's server; the root package binds the carriers it serves and runs them.
type ServerFuncs struct {
	Serve       func(ctx context.Context, ln net.Listener, upstream Network) error   // serves the Stream carrier until it fails or ctx ends
	ServePacket func(ctx context.Context, pc net.PacketConn, upstream Network) error // serves the Packet carrier until it fails or ctx ends
	Close       func() error                                                         // optional; releases what NewServer acquired, and may run while Serve or ServePacket are still returning
}

// server is the Server that RegisterLayer derives from s.NewServer.
func (s Spec) server(inner Transport, upstream Network, opts Options) (Server, error) {
	planes := inner.Planes() & (s.Requires | s.Preserves)
	if planes == 0 {
		return nil, fmt.Errorf("serve over %v: %w", inner.Planes(), ErrUnsupported)
	}
	funcs, err := s.NewServer(opts)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %w", err, ErrInvalidChain)
	case funcs == nil:
		return nil, fmt.Errorf("NewServer returned nil: %w", ErrInvalidChain)
	case funcs.Serve == nil && (s.Requires|s.Preserves)&Stream != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no Serve for %v", Stream))
	case funcs.ServePacket == nil && (s.Requires|s.Preserves)&Packet != 0:
		return nil, reject(funcs.Close, fmt.Errorf("no ServePacket for %v", Packet))
	}
	var listen func(context.Context) (net.Listener, error)
	var listenPacket func(context.Context) (net.PacketConn, error)
	if planes&Stream != 0 {
		listen = inner.Listen
	}
	if planes&Packet != 0 {
		listenPacket = inner.ListenPacket
	}
	srv := serverutils.NewPlaneServer(listen, listenPacket,
		func(ctx context.Context, ln net.Listener) error { return funcs.Serve(ctx, ln, upstream) },
		func(ctx context.Context, pc net.PacketConn) error { return funcs.ServePacket(ctx, pc, upstream) },
	)
	return assembledServer{srv, closeOnce(funcs.Close, inner)}, nil
}

// assembledServer is a declared server; the engine built its inner Transport, so Close releases it too.
type assembledServer struct {
	*serverutils.Server
	close func() error
}

// Close stops the server as the lifecycle does, then releases it and its inner Transport once.
func (a assembledServer) Close() error {
	return errors.Join(a.Server.Close(), a.close())
}

// dgram is the built-in client-only adapter that dials its Stream carrier as best-effort datagrams to the carrier's peer.
var dgram = Spec{
	Kind:     KindAdapter,
	Requires: Stream,
	Provides: Packet,
	Lossy:    Packet,
	NewAdapter: func(Options) (*AdapterFuncs, error) {
		return &AdapterFuncs{Packet: &Link{Over: Stream, Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
			return netutils.StreamPacket(carrier, carrier.RemoteAddr()), nil
		}}}, nil
	},
}
