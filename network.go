package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

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

// borrowed hides everything but Network on an injected base, so a constructor returning it hands
// back nothing closable.
type borrowed struct{ Network }

// Lossy forwards what the borrowed network reports.
func (b borrowed) Lossy(network string) bool {
	return isLossy(b.Network, network)
}

var native Network = &NetworkFuncs{
	DialContextFunc:  dialNative,
	ListenFunc:       (&net.ListenConfig{}).Listen,
	ListenPacketFunc: (&net.ListenConfig{}).ListenPacket,
}

// dialNative binds datagram networks to an unconnected socket; the rest go through net.Dialer.
func dialNative(ctx context.Context, network, address string) (net.Conn, error) {
	if _, plane, _ := lookupBase(network); plane == Packet {
		return netutils.DialPacket(ctx, network, address, (&net.ListenConfig{}).ListenPacket)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// byName is the Network a nil Engine.Base or Engine.Upstream stands for, resolving each call by its network name.
type byName struct{}

// resolve is network's registered implementation, else the system for tcp, udp, unix, unixgram and their families, else a Network refusing every call.
func (byName) resolve(network string) Network {
	base, _, _ := lookupBase(network)
	if ns, _ := lookupNetwork(base); ns.Network != nil {
		return ns.Network
	}
	switch base {
	case "tcp", "udp", "unix", "unixgram":
		return native
	}
	return NetworkFuncs{}
}

func (n byName) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.resolve(network).DialContext(ctx, network, address)
}

func (n byName) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return n.resolve(network).Listen(ctx, network, address)
}

func (n byName) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return n.resolve(network).ListenPacket(ctx, network, address)
}

// Lossy forwards what network's resolved implementation reports.
func (n byName) Lossy(network string) bool {
	return isLossy(n.resolve(network), network)
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

// restricted refuses Network operations outside the chain's declared planes before they reach the layer.
type restricted struct {
	network Network
	plane   Plane
}

func (n restricted) check(op, network string, want Plane) error {
	if _, p, ok := lookupBase(network); !ok || p&want&n.plane == 0 {
		return fmt.Errorf("%s %s: %w", op, network, ErrUnsupported)
	}
	return nil
}

func (n restricted) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := n.check("dial", network, Stream|Packet); err != nil {
		return nil, err
	}
	return n.network.DialContext(ctx, network, address)
}

func (n restricted) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if err := n.check("listen", network, Stream); err != nil {
		return nil, err
	}
	return n.network.Listen(ctx, network, address)
}

func (n restricted) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if err := n.check("listen packet", network, Packet); err != nil {
		return nil, err
	}
	return n.network.ListenPacket(ctx, network, address)
}

func (n restricted) Close() error {
	return closeIf(n.network)
}

// Lossy forwards what the restricted network reports.
func (n restricted) Lossy(network string) bool {
	return isLossy(n.network, network)
}
