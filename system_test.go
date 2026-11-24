package permuteproxy

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// system is testutils.System dialing datagram networks unconnected, as protocols/local does.
type system struct{ testutils.System }

func (s system) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6", "unixgram":
		return netutils.DialPacket(ctx, network, address, s.ListenPacket)
	}
	return s.System.DialContext(ctx, network, address)
}

// dgram is protocols/local's layer of that name, declared alike.
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
