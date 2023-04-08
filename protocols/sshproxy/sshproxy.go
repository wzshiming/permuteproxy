package sshproxy

import (
	"context"

	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"

	"github.com/wzshiming/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/protocols"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

// NewSSHProxyDialer ssh proxy dialer
func NewSSHProxyDialer(ctx context.Context, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	proxy, ok := permuteproxy.FromContext(ctx)
	if !ok || proxy.Dialer == nil {
		return nil, permuteproxy.ErrNoProxy
	}

	u := protocols.EncodeURLWithMetadata("ssh", "localhost", metadata, KeyUsername, KeyPassword)
	dialer, err := sshproxy.NewDialer(u)
	if err != nil {
		return nil, err
	}

	dialer.ProxyDial = proxy.Dialer.DialContext
	return dialer, nil
}

type runner struct {
	listener permuteproxy.Listener
	server   *sshproxy.SimpleServer
}

func NewSSHProxyRunner(listener permuteproxy.Listener, metadata permuteproxy.Metadata) (permuteproxy.Runner, error) {
	u := protocols.EncodeURLWithMetadata("ssh", "localhost", metadata, KeyUsername, KeyPassword)
	server, err := sshproxy.NewSimpleServer(u)
	if err != nil {
		return nil, err
	}
	server.BytesPool = pool.Bytes
	server.Listener = listener
	return &runner{
		listener: listener,
		server:   server,
	}, nil
}

func (r *runner) Run(ctx context.Context) error {
	return r.server.Run(ctx)
}

func (r *runner) Close() error {
	return r.listener.Close()
}
