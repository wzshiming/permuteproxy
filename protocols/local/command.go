package local

import (
	"context"
	"net"

	"github.com/google/shlex"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

type command struct {
	CommandDialer permuteproxy.CommandDialer
}

var localAddr = netutils.NewNetAddr("cmd", "")

func (c *command) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	cmd, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	remoteAddr := netutils.NewNetAddr(network, address)

	commandDialer := c.CommandDialer
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.CommandDialer != nil {
		commandDialer = proxy.CommandDialer
	}

	return cmdutils.NewCommandListener(ctx, commandDialer, localAddr, remoteAddr, cmd)
}

func (c *command) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cmd, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	remoteAddr := netutils.NewNetAddr(network, address)

	commandDialer := c.CommandDialer
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.CommandDialer != nil {
		commandDialer = proxy.CommandDialer
	}

	return cmdutils.NewCommandDialContext(ctx, commandDialer, localAddr, remoteAddr, cmd)
}
