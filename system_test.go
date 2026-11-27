package permuteproxy

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// dgram is protocols/local's layer of that name, declared alike.
var dgram = LayerSpec{
	Requires: Stream,
	Provides: Packet,
	Lossy:    Packet,
	NewAdapter: func(Options) (*AdapterFuncs, error) {
		return &AdapterFuncs{Packet: &Link{Over: Stream, Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
			c, err := carrier(ctx)
			if err != nil {
				return nil, err
			}
			return netutils.StreamPacket(c, c.RemoteAddr()), nil
		}}}, nil
	},
}
