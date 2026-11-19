package permuteproxy

import (
	"context"
	"fmt"
	"net"
)

// AdapterFuncs declares what an adapter does to its carrier, one Link per plane it offers.
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
		if link == nil {
			return inner.Dial(ctx, plane)
		}
		carrier, err := inner.Dial(ctx, link.carrier(plane))
		if err != nil {
			return nil, err
		}
		return link.Client(ctx, carrier)
	}
	switch link := funcs.Stream; {
	case link == nil:
		t.ListenFunc = inner.Listen
	case link.carrier(Stream) == Stream:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) {
			ln, err := inner.Listen(ctx)
			if err != nil {
				return nil, err
			}
			return link.Listener(ln)
		}
	default:
		t.ListenFunc = func(ctx context.Context) (net.Listener, error) {
			pc, err := inner.ListenPacket(ctx)
			if err != nil {
				return nil, err
			}
			return link.PacketListener(pc)
		}
	}
	switch link := funcs.Packet; {
	case link == nil:
		t.ListenPacketFunc = inner.ListenPacket
	case link.carrier(Packet) == Packet:
		t.ListenPacketFunc = func(ctx context.Context) (net.PacketConn, error) {
			pc, err := inner.ListenPacket(ctx)
			if err != nil {
				return nil, err
			}
			return link.PacketConn(pc)
		}
	}
	return t, nil
}
