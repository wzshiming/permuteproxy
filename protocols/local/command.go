package local

import (
	"context"
	"errors"
	"net"

	"github.com/google/shlex"

	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var localAddr = netutils.NewNetAddr("cmd", "")

func splitCommand(address string) ([]string, error) {
	args, err := shlex.Split(address)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	return args, nil
}

func (l *Local) dialCommand(ctx context.Context, network, address string) (net.Conn, error) {
	args, err := splitCommand(address)
	if err != nil {
		return nil, err
	}
	return cmdutils.DialContext(ctx, l.Command, localAddr, netutils.NewNetAddr(network, address), args)
}

func (l *Local) listenCommand(ctx context.Context, network, address string) (net.Listener, error) {
	args, err := splitCommand(address)
	if err != nil {
		return nil, err
	}
	return cmdutils.Listen(ctx, l.Command, localAddr, netutils.NewNetAddr(network, address), args)
}
