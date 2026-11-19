package permuteproxy

import (
	"context"
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

// adapt is the Adapt that RegisterLayer derives from s.NewAdapter.
func (s Spec) adapt(inner Transport, opts Options) (Transport, error) {
	funcs, err := s.NewAdapter(opts)
	if err != nil {
		return nil, err
	}
	t := TransportFuncs{Plane: s.Provides | (inner.Planes() & s.Preserves)}
	t.DialFunc = func(ctx context.Context, plane Plane) (net.Conn, error) {
		link := funcs.link(plane)
		carrier, err := inner.Dial(ctx, link.carrier(plane))
		if err != nil {
			return nil, err
		}
		return link.Client(ctx, carrier)
	}
	switch link := funcs.Stream; {
	case link == nil:
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
	if link := funcs.Packet; link != nil && link.carrier(Packet) == Packet {
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
