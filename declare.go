package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/serverutils"
)

// AdapterFuncs declares an adapter per plane; a preserved plane without a Link passes through unchanged.
type AdapterFuncs struct {
	Stream *Link        // how the layer provides Stream
	Packet *Link        // how the layer provides Packet
	Close  func() error // optional; releases what NewAdapter acquired
}

// Link derives one plane from a carrier of one plane, through a client and a server form.
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
		return nil, fmt.Errorf("%w: %w", err, ErrInvalidChain)
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
		carrier, err := inner.Dial(ctx, link.carrier(plane))
		return apply(carrier, err, func(conn net.Conn) (net.Conn, error) { return link.Client(ctx, conn) })
	}
	// covers admits a server form only for its own pair, so the one set picks the carrier.
	switch link := funcs.Stream; {
	case link == nil:
		t.ListenFunc = inner.Listen
	case link.Listener != nil:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) {
			ln, err := inner.Listen(ctx)
			return apply(ln, err, link.Listener)
		}
	case link.PacketListener != nil:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) {
			pc, err := inner.ListenPacket(ctx)
			return apply(pc, err, link.PacketListener)
		}
	}
	switch link := funcs.Packet; {
	case link == nil:
		t.ListenPacketFunc = inner.ListenPacket
	case link.PacketConn != nil:
		t.ListenPacketFunc = func(ctx context.Context) (net.PacketConn, error) {
			pc, err := inner.ListenPacket(ctx)
			return apply(pc, err, link.PacketConn)
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

// assembled is a declared layer's Transport; adapter code never sees inner, so Close releases it too.
type assembled struct {
	TransportFuncs
	close func() error
}

// Close releases the layer and then its inner Transport, once.
func (a assembled) Close() error {
	return a.close()
}

// apply hands a carrier just obtained to f, closing it when f fails.
func apply[C io.Closer, R any](carrier C, err error, f func(C) (R, error)) (r R, _ error) {
	if err != nil {
		return r, err
	}
	if r, err = f(carrier); err != nil {
		carrier.Close()
	}
	return r, err
}

// ClientFuncs declares a proxy's client; the root package admits the networks Spec.Networks lists and derives udp dials.
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
		return nil, fmt.Errorf("no Dial for %v: %w", Stream, ErrInvalidChain)
	case funcs.ListenPacket == nil && (s.Provides|s.Preserves)&Packet != 0:
		return nil, fmt.Errorf("no ListenPacket for %v: %w", Packet, ErrInvalidChain)
	}
	n := NetworkFuncs{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			switch base, plane := s.admit(network); {
			case plane == Stream && funcs.Dial != nil:
				return funcs.Dial(ctx, inner, network, address)
			case base == "udp" && funcs.ListenPacket != nil:
				return funcs.dialUDP(ctx, inner, local, network, address)
			}
			return nil, fmt.Errorf("dial %s: %w", network, ErrUnsupported)
		},
		ListenPacketFunc: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			if _, plane := s.admit(network); plane != Packet || funcs.ListenPacket == nil {
				return nil, fmt.Errorf("listen packet %s: %w", network, ErrUnsupported)
			}
			return funcs.ListenPacket(ctx, inner, local, network, address)
		},
	}
	return assembledNetwork{n, closeOnce(funcs.Close, inner)}, nil
}

// assembledNetwork is a declared client's Network; the engine built its inner Transport, so Close releases it too.
type assembledNetwork struct {
	NetworkFuncs
	close func() error
}

// Close releases the client and then its inner Transport, once.
func (a assembledNetwork) Close() error {
	return a.close()
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
}

// server is the Server that RegisterLayer derives from s.NewServer.
func (s Spec) server(inner Transport, upstream Network, opts Options) (Server, error) {
	funcs, err := s.NewServer(opts)
	if err != nil {
		return nil, err
	}
	var listen func(context.Context) (net.Listener, error)
	var listenPacket func(context.Context) (net.PacketConn, error)
	planes := inner.Planes() & (s.Requires | s.Preserves)
	if planes&Stream != 0 {
		listen = inner.Listen
	}
	if planes&Packet != 0 {
		listenPacket = inner.ListenPacket
	}
	return serverutils.NewPlaneServer(listen, listenPacket,
		func(ctx context.Context, ln net.Listener) error { return funcs.Serve(ctx, ln, upstream) },
		func(ctx context.Context, pc net.PacketConn) error { return funcs.ServePacket(ctx, pc, upstream) },
	), nil
}
