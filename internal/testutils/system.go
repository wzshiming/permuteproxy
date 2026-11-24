package testutils

import (
	"context"
	"net"
)

// System dials and listens through the standard library.
type System struct{}

func (System) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (System) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, network, address)
}

func (System) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}
