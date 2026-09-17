package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
)

var ErrUnsupported = errors.New("unsupported")

type Network interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type NetworkFuncs struct {
	DialContextFunc  func(ctx context.Context, network, address string) (net.Conn, error)
	ListenFunc       func(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacketFunc func(ctx context.Context, network, address string) (net.PacketConn, error)
}

func (n NetworkFuncs) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if n.DialContextFunc == nil {
		return nil, fmt.Errorf("dial %s: %w", network, ErrUnsupported)
	}
	return n.DialContextFunc(ctx, network, address)
}

func (n NetworkFuncs) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if n.ListenFunc == nil {
		return nil, fmt.Errorf("listen %s: %w", network, ErrUnsupported)
	}
	return n.ListenFunc(ctx, network, address)
}

func (n NetworkFuncs) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if n.ListenPacketFunc == nil {
		return nil, fmt.Errorf("listen packet %s: %w", network, ErrUnsupported)
	}
	return n.ListenPacketFunc(ctx, network, address)
}

type Transport interface {
	Planes() Plane
	Dial(ctx context.Context, plane Plane) (net.Conn, error)
	Listen(ctx context.Context) (net.Listener, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

type TransportFuncs struct {
	Plane            Plane
	DialFunc         func(ctx context.Context, plane Plane) (net.Conn, error)
	ListenFunc       func(ctx context.Context) (net.Listener, error)
	ListenPacketFunc func(ctx context.Context) (net.PacketConn, error)
}

func (t TransportFuncs) Planes() Plane {
	return t.Plane
}

func (t TransportFuncs) Dial(ctx context.Context, plane Plane) (net.Conn, error) {
	if t.DialFunc == nil || t.Plane&plane != plane {
		return nil, fmt.Errorf("dial %v: %w", plane, ErrUnsupported)
	}
	return t.DialFunc(ctx, plane)
}

func (t TransportFuncs) Listen(ctx context.Context) (net.Listener, error) {
	if t.ListenFunc == nil {
		return nil, fmt.Errorf("listen: %w", ErrUnsupported)
	}
	return t.ListenFunc(ctx)
}

func (t TransportFuncs) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if t.ListenPacketFunc == nil {
		return nil, fmt.Errorf("listen packet: %w", ErrUnsupported)
	}
	return t.ListenPacketFunc(ctx)
}

var native Network = &NetworkFuncs{
	DialContextFunc:  (&net.Dialer{}).DialContext,
	ListenFunc:       (&net.ListenConfig{}).Listen,
	ListenPacketFunc: (&net.ListenConfig{}).ListenPacket,
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
	if plane == Stream && b.stream != "" {
		return b.network.DialContext(ctx, b.stream, b.address)
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
