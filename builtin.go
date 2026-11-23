package permuteproxy

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// dgram is the built-in client-only adapter that dials its Stream carrier as best-effort datagrams to the carrier's peer.
var dgram = LayerSpec{
	Kind:     LayerAdapter,
	Requires: Stream,
	Provides: Packet,
	Lossy:    Packet,
	NewAdapter: func(Options) (*AdapterFuncs, error) {
		return &AdapterFuncs{Packet: &Link{Over: Stream, Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
			return netutils.StreamPacket(carrier, carrier.RemoteAddr()), nil
		}}}, nil
	},
}
