package command

import (
	"context"
	"net"

	"github.com/google/shlex"
	"github.com/wzshiming/commandproxy"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var Command = &command{
	CommandDialer: netutils.CommandDialFunc(func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		proxy := commandproxy.ProxyCommand(ctx, name, args...)
		// proxy.Stderr = os.Stderr
		return proxy.Stdio()
	}),
}

type command struct {
	CommandDialer netutils.CommandDialer
}

var localAddr = netutils.NewNetAddr("cmd", "")

func (c *command) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	cmd, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	remoteAddr := netutils.NewNetAddr(network, address)
	return netutils.NewCommandListener(ctx, c.CommandDialer, localAddr, remoteAddr, cmd)
}

func (c *command) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cmd, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	remoteAddr := netutils.NewNetAddr(network, address)
	return netutils.NewCommandDialContext(ctx, c.CommandDialer, localAddr, remoteAddr, cmd)
}
