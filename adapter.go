package permuteproxy

import (
	"context"
	"fmt"
	"net"
)

// AdapterFuncs declares an adapter per plane; a preserved plane without a Link passes through unchanged.
type AdapterFuncs struct {
	Stream *Link        // how the layer provides Stream
	Packet *Link        // how the layer provides Packet
	Close  func() error // optional; releases what NewAdapter acquired
}

// Link derives one plane from a carrier of one plane through a client form and, for Stream, a server form. Each function obtains its carrier by calling carrier, so what it checks first fails before any I/O; Dial may call it as often as it needs and not at all when a carrier it kept serves the dial. A function owns each carrier it obtains, also when it fails.
type Link struct {
	Over         Plane                                                                                                  // carrier plane consumed; zero means the provided plane itself
	Dial         func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error)           // a Packet carrier is also a net.PacketConn with a default peer
	Listen       func(ctx context.Context, carrier func(context.Context) (net.Listener, error)) (net.Listener, error)   // Stream over a Stream carrier
	ListenPacket func(ctx context.Context, carrier func(context.Context) (net.PacketConn, error)) (net.Listener, error) // Stream over a Packet carrier
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
	return (l.Listen == nil || p == Stream && over == Stream) &&
		(l.ListenPacket == nil || p == Stream && over == Packet)
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

// adapt builds over inner the adapter s.NewAdapter declares, offering of its planes those in plane, what the chain exposes above it.
func (s LayerSpec) adapt(inner Transport, opts Options, plane Plane) (Transport, error) {
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
	t := TransportFuncs{Plane: plane & (s.Provides | (inner.Planes() & s.Preserves))}
	t.DialFunc = func(ctx context.Context, plane Plane) (net.Conn, error) {
		link := funcs.link(plane)
		if link == nil {
			return inner.Dial(ctx, plane)
		}
		if link.Dial == nil {
			return nil, fmt.Errorf("dial %v: %w", plane, ErrUnsupported)
		}
		return link.Dial(ctx, func(ctx context.Context) (net.Conn, error) { return inner.Dial(ctx, link.carrier(plane)) })
	}
	// covers admits a server form only for its own pair, so the one set picks the carrier.
	switch link := funcs.Stream; {
	case link == nil:
		t.ListenFunc = inner.Listen
	case link.Listen != nil:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) { return link.Listen(ctx, inner.Listen) }
	case link.ListenPacket != nil:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) { return link.ListenPacket(ctx, inner.ListenPacket) }
	}
	if funcs.Packet == nil {
		t.ListenPacketFunc = inner.ListenPacket
	}
	// Adapter code never sees inner, so Close releases it too.
	return assembled{t, closeOnce(funcs.Close, inner)}, nil
}
