package sshproxy

import (
	"context"
	"net"
	"net/url"

	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"

	"github.com/wzshiming/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

var options = []string{
	"identity_data",
	"identity_file",
	"authorized_data",
	"authorized_file",
	"hostkey_data",
	"hostkey_file",
}

// endpoint renders the options as the URL form sshproxy parses; the host is a placeholder since
// the inner transport decides where connections go.
func endpoint(opts permuteproxy.Options) string {
	u := url.URL{
		Scheme:   "ssh",
		Host:     "localhost",
		User:     protoutils.Userinfo(opts, KeyUsername, KeyPassword),
		RawQuery: protoutils.Values(opts, KeyUsername, KeyPassword).Encode(),
	}
	return u.String()
}

// client keeps the cached SSH connection reachable for Close.
type client struct {
	permuteproxy.Network
	dialer *sshproxy.Dialer
}

func (c *client) Close() error {
	return c.dialer.Close()
}

func NewClient(inner permuteproxy.Transport, _ permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	dialer, err := sshproxy.NewDialer(endpoint(opts))
	if err != nil {
		return nil, err
	}
	dialer.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return inner.Dial(ctx, permuteproxy.Stream)
	}
	return &client{protoutils.DialNetwork(dialer.DialContext, "tcp", "tcp4", "tcp6", "unix"), dialer}, nil
}

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	srv, err := sshproxy.NewSimpleServer(endpoint(opts))
	if err != nil {
		return nil, err
	}
	srv.ProxyDial = upstream.DialContext
	srv.ProxyListen = upstream.Listen
	srv.BytesPool = pool.Bytes
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		srv.Context = ctx
		return srv.Serve(ln)
	}), nil
}
