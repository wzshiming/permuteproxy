package local

import (
	"context"
	"fmt"
	"net"
)

type netCatTCP struct {
	cmd *command
}

func (n *netCatTCP) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	command := ""
	switch network {
	case "tcp4":
		command = fmt.Sprintf("nc -4 %s %s", host, port)
	case "tcp6":
		command = fmt.Sprintf("nc -6 %s %s", host, port)
	default:
		command = fmt.Sprintf("nc %s %s", host, port)
	}
	return n.cmd.DialContext(ctx, "cmd", command)
}

func (n *netCatTCP) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	command := ""
	switch network {
	case "tcp4":
		command = fmt.Sprintf("nc -4l %s %s", host, port)
	case "tcp6":
		command = fmt.Sprintf("nc -6l %s %s", host, port)
	default:
		command = fmt.Sprintf("nc -l %s %s", host, port)
	}
	return n.cmd.Listen(ctx, "cmd", command)
}
