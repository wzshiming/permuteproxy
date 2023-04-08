package sshproxy

import (
	"context"
	"net"

	"github.com/google/shlex"
	"github.com/wzshiming/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

// NewSSHProxyCommandDialer creates a new Dialer that uses the sshproxy package to
func NewSSHProxyCommandDialer(d permuteproxy.Dialer, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	u := protocols.EncodeURLWithMetadata("ssh", "localhost", metadata, KeyUsername, KeyPassword)
	dialer, err := sshproxy.NewDialer(u)
	if err != nil {
		return nil, err
	}
	dialer.ProxyDial = d.DialContext

	return permuteproxy.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		cmd, err := shlex.Split(address)
		if err != nil {
			return nil, err
		}
		return dialer.CommandDialContext(ctx, cmd[0], cmd[1:]...)
	}), nil
}
