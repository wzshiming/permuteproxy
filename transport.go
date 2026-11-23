package permuteproxy

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// Transport is a chain built down to its endpoint, offering the endpoint on each plane it has.
type Transport interface {
	// Planes is the set of planes Dial, Listen and ListenPacket serve.
	Planes() Plane
	// Dial connects to the endpoint on one plane; a Packet conn is also a net.PacketConn whose default peer is the endpoint.
	Dial(ctx context.Context, plane Plane) (net.Conn, error)
	// Listen accepts Stream connections at the endpoint.
	Listen(ctx context.Context) (net.Listener, error)
	// ListenPacket binds a Packet socket at the endpoint.
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

// TransportFuncs is a Transport of functions, each refusing with ErrUnsupported while it is nil or its plane is outside Plane.
type TransportFuncs struct {
	Plane            Plane                                                    // the planes it offers
	DialFunc         func(ctx context.Context, plane Plane) (net.Conn, error) // implements Dial
	ListenFunc       func(ctx context.Context) (net.Listener, error)          // implements Listen
	ListenPacketFunc func(ctx context.Context) (net.PacketConn, error)        // implements ListenPacket
}

// Planes returns Plane.
func (t TransportFuncs) Planes() Plane {
	return t.Plane
}

// Dial calls DialFunc for Stream or Packet within Plane.
func (t TransportFuncs) Dial(ctx context.Context, plane Plane) (net.Conn, error) {
	if t.DialFunc == nil || (plane != Stream && plane != Packet) || t.Plane&plane == 0 {
		return nil, fmt.Errorf("dial %v: %w", plane, ErrUnsupported)
	}
	return t.DialFunc(ctx, plane)
}

// Listen calls ListenFunc when Plane has Stream.
func (t TransportFuncs) Listen(ctx context.Context) (net.Listener, error) {
	if t.ListenFunc == nil || t.Plane&Stream == 0 {
		return nil, fmt.Errorf("listen: %w", ErrUnsupported)
	}
	return t.ListenFunc(ctx)
}

// ListenPacket calls ListenPacketFunc when Plane has Packet.
func (t TransportFuncs) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if t.ListenPacketFunc == nil || t.Plane&Packet == 0 {
		return nil, fmt.Errorf("listen packet: %w", ErrUnsupported)
	}
	return t.ListenPacketFunc(ctx)
}

func closeIf(v any) error {
	if c, ok := v.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// pinned gates a layer's result to its resolved plane; Close reaches the result when it has one.
type pinned struct {
	TransportFuncs
	result Transport
}

func (p pinned) Close() error {
	return closeIf(p.result)
}

// split dials through dial and listens through listen, both on dial's planes; Close reaches dial.
func split(dial, listen Transport) Transport {
	return pinned{TransportFuncs{Plane: dial.Planes(), DialFunc: dial.Dial, ListenFunc: listen.Listen, ListenPacketFunc: listen.ListenPacket}, dial}
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
		next, err := r.specs[i].adapt(t, r.layers[i].Options.clone())
		if err != nil {
			closeIf(t)
			return nil, fmt.Errorf("layer %q: %w", r.layers[i].Scheme, err)
		}
		t = pinned{TransportFuncs{Plane: r.planes[i], DialFunc: next.Dial, ListenFunc: next.Listen, ListenPacketFunc: next.ListenPacket}, next}
	}
	return t, nil
}
