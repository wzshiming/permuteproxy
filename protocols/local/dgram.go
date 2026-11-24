package local

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// dgram is the client-only adapter that dials its Stream carrier as best-effort datagrams to the carrier's peer.
var dgram = permuteproxy.LayerSpec{
	Kind:     permuteproxy.LayerAdapter,
	Requires: permuteproxy.Stream,
	Provides: permuteproxy.Packet,
	Lossy:    permuteproxy.Packet,
	NewAdapter: func(permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
		return &permuteproxy.AdapterFuncs{Packet: &permuteproxy.Link{Over: permuteproxy.Stream, Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
			return netutils.StreamPacket(carrier, carrier.RemoteAddr()), nil
		}}}, nil
	},
}
