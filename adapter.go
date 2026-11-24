package permuteproxy

import (
	"context"
	"fmt"
	"net"
)

// AdapterFuncs declares an adapter per plane; a preserved plane without a Link passes through unchanged.
type AdapterFuncs struct {
	Stream       *Link        // how the layer provides Stream
	Packet       *Link        // how the layer provides Packet
	BeforeDial   func() error // optional; runs before a Dial obtains a link's carrier, failing the Dial with its error
	BeforeListen func() error // optional; runs before a Listen obtains a link's carrier, failing the Listen with its error
	Close        func() error // optional; releases what NewAdapter acquired
}

// Link derives one plane from a carrier of one plane through a client form and, for Stream, a server form, each function owning the carrier it is handed, also when it fails.
type Link struct {
	Over           Plane                                                         // carrier plane consumed; zero means the provided plane itself
	Client         func(ctx context.Context, carrier net.Conn) (net.Conn, error) // a Packet carrier is also a net.PacketConn with a default peer
	Listener       func(ln net.Listener) (net.Listener, error)                   // Stream over a Stream carrier
	PacketListener func(pc net.PacketConn) (net.Listener, error)                 // Stream over a Packet carrier
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
		(l.PacketListener == nil || p == Stream && over == Packet)
}

// covers reports how funcs falls short of the planes s declares.
func (s LayerSpec) covers(funcs *AdapterFuncs) error {
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

// adapt builds over inner the adapter s.NewAdapter declares.
func (s LayerSpec) adapt(inner Transport, opts Options) (Transport, error) {
	funcs, err := s.NewAdapter(opts)
	switch {
	case err != nil:
		return nil, invalid(err)
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
	if funcs.Packet == nil {
		t.ListenPacketFunc = inner.ListenPacket
	}
	return assembled{t, closeOnce(funcs.Close, inner)}, nil
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
