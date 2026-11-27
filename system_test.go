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
		return &AdapterFuncs{Packet: &Link{Over: Stream, Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
			return netutils.StreamPacket(carrier, carrier.RemoteAddr()), nil
		}}}, nil
	},
}
