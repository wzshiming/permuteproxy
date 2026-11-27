package local

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// dgram is the client-only adapter that dials its Stream carrier as best-effort datagrams to the carrier's peer.
var dgram = permuteproxy.LayerSpec{
	Requires: permuteproxy.Stream,
	Provides: permuteproxy.Packet,
	Lossy:    permuteproxy.Packet,
	NewAdapter: func(permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
		return &permuteproxy.AdapterFuncs{Packet: &permuteproxy.Link{Over: permuteproxy.Stream, Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
			c, err := carrier(ctx)
			if err != nil {
				return nil, err
			}
			return netutils.StreamPacket(c, c.RemoteAddr()), nil
		}}}, nil
	},
}
