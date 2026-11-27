package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// borrowed forwards only Network and Lossy of an injected base, never its Close.
type borrowed struct{ Network }

// Lossy forwards what the borrowed network reports.
func (b borrowed) Lossy(network string) bool {
	return isLossy(b.Network, network)
}

// byName is the Network an engine's nil Base or Upstream stands for, resolving each call by its network name.
type byName struct{}

// resolve is the registered implementation of network's base, else a Network refusing every call.
func (byName) resolve(network string) Network {
	base, _, _ := lookupBase(network)
	if ns, _ := lookupNetwork(base); ns.Network != nil {
		return ns.Network
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

func orByName(n Network) Network {
	if n != nil {
		return n
	}
	return byName{}
}
