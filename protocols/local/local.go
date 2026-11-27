// Package local registers the system's networks tcp, udp, unix and unixgram.
package local

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// Local is the Network of the system's own networking.
type Local struct{}

// Network is the registered implementation of tcp, udp, unix and unixgram.
var Network = &Local{}

func (l *Local) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6", "unixgram":
		return netutils.DialPacket(ctx, network, address, l.ListenPacket)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	return conn, unsupported(err)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
	return ln, unsupported(err)
}

func (l *Local) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	return pc, unsupported(err)
}

// unsupported marks the system's refusal of a network it does not know as ErrUnsupported.
func unsupported(err error) error {
	if errors.As(err, new(net.UnknownNetworkError)) {
		return fmt.Errorf("%w: %w", err, permuteproxy.ErrUnsupported)
	}
	return err
}
