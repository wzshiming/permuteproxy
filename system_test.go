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

// Runs after chain_test.go's init, so atRootInit still holds the networks unimplemented.
func init() {
	for _, name := range []string{"tcp", "udp", "unix", "unixgram"} {
		ImplementNetwork(name, system{})
	}
}
