package sshproxy

import (
	"context"
	"net"

	"github.com/wzshiming/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

// NewSSHProxyCommandNetCatUnixDialer creates a new Dialer that uses the sshproxy package to
func NewSSHProxyCommandNetCatUnixDialer(d permuteproxy.Dialer, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	u := protocols.EncodeURLWithMetadata("ssh", "localhost", metadata, KeyUsername, KeyPassword)
	dialer, err := sshproxy.NewDialer(u)
	if err != nil {
		return nil, err
	}
	dialer.ProxyDial = d.DialContext

	return permuteproxy.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		cmd := []string{"nc", "-U", host, port}
		return dialer.CommandDialContext(ctx, cmd[0], cmd[1:]...)
	}), nil
}
