package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/wzshiming/permuteproxy/internal/netutils"
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
	if t.DialFunc == nil || (plane != Stream && plane != Packet) || t.Plane&plane == 0 {
		return nil, fmt.Errorf("dial %v: %w", plane, ErrUnsupported)
	}
	return t.DialFunc(ctx, plane)
}

func (t TransportFuncs) Listen(ctx context.Context) (net.Listener, error) {
	if t.ListenFunc == nil || t.Plane&Stream == 0 {
		return nil, fmt.Errorf("listen: %w", ErrUnsupported)
	}
	return t.ListenFunc(ctx)
}

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

// borrowed hides everything but Network on an injected base, so a constructor returning it hands
// back nothing closable.
type borrowed struct{ Network }

var native Network = &NetworkFuncs{
	DialContextFunc:  dialNative,
	ListenFunc:       (&net.ListenConfig{}).Listen,
	ListenPacketFunc: (&net.ListenConfig{}).ListenPacket,
}

// dialNative binds datagram networks to an unconnected socket; the rest go through net.Dialer.
func dialNative(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6", "unixgram":
		return netutils.DialPacket(ctx, network, address, (&net.ListenConfig{}).ListenPacket)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
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
