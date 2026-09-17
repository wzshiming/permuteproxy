package protoutils

import (
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/wzshiming/permuteproxy"
)

// DialNetwork exposes a client dial as a Network limited to the named networks; anything else
// is refused before any I/O happens.
func DialNetwork(dial func(ctx context.Context, network, address string) (net.Conn, error), networks ...string) permuteproxy.Network {
	return permuteproxy.NetworkFuncs{DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		if !slices.Contains(networks, network) {
			return nil, fmt.Errorf("dial %s: %w", network, permuteproxy.ErrUnsupported)
		}
		return dial(ctx, network, address)
	}}
}
