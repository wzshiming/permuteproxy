package local

import (
	"context"
	"fmt"
	"net"
)

type netCatUnix struct {
	cmd *command
}

func (n *netCatUnix) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.cmd.DialContext(ctx, "cmd", fmt.Sprintf("nc -U %s", address))
}

func (n *netCatUnix) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return n.cmd.Listen(ctx, "cmd", fmt.Sprintf("nc -Ul %s", address))
}
