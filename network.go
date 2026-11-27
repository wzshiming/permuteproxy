package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// Plane is a set of the kinds of carrier a transport offers: byte streams, datagrams or both.
type Plane uint8

const (
	Stream Plane = 1 << iota // reliable ordered byte streams, as tcp carries
	Packet                   // datagrams each with its peer, as udp carries
)

// String names the planes in p joined by '|', or "none".
func (p Plane) String() string {
	var names []string
	if p&Stream != 0 {
		names = append(names, "stream")
	}
	if p&Packet != 0 {
		names = append(names, "packet")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}

// ErrUnsupported is returned, before any I/O, for an operation a network, transport or layer does not offer.
var ErrUnsupported = errors.New("unsupported")

// Network dials and listens by network name, as the net package does.
type Network interface {
	// DialContext connects to address; on a datagram network the conn is also a net.PacketConn.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Listen accepts stream connections at address.
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	// ListenPacket binds a datagram socket at address that reaches any peer.
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

// LossyNetwork is the optional interface of a Network whose datagram networks may lose datagram boundaries.
type LossyNetwork interface {
	Lossy(network string) bool // reports whether datagrams on network, a base name such as udp, may arrive merged or split
}

// isLossy reports whether n says the base network of network loses datagram boundaries.
func isLossy(n Network, network string) bool {
	l, ok := n.(LossyNetwork)
	base, _, _ := lookupBase(network)
	return ok && l.Lossy(base)
}

// NetworkFuncs is a Network of functions, each refusing with ErrUnsupported while it is nil.
type NetworkFuncs struct {
	DialContextFunc  func(ctx context.Context, network, address string) (net.Conn, error)       // implements DialContext
	ListenFunc       func(ctx context.Context, network, address string) (net.Listener, error)   // implements Listen
	ListenPacketFunc func(ctx context.Context, network, address string) (net.PacketConn, error) // implements ListenPacket
}

// DialContext calls DialContextFunc.
func (n NetworkFuncs) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if n.DialContextFunc == nil {
		return nil, fmt.Errorf("dial %s: %w", network, ErrUnsupported)
	}
	return n.DialContextFunc(ctx, network, address)
}

// Listen calls ListenFunc.
func (n NetworkFuncs) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if n.ListenFunc == nil {
		return nil, fmt.Errorf("listen %s: %w", network, ErrUnsupported)
	}
	return n.ListenFunc(ctx, network, address)
}

// ListenPacket calls ListenPacketFunc.
func (n NetworkFuncs) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if n.ListenPacketFunc == nil {
		return nil, fmt.Errorf("listen packet %s: %w", network, ErrUnsupported)
	}
	return n.ListenPacketFunc(ctx, network, address)
}

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
