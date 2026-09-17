package socks5

import (
	"context"
	"net"
	"time"

	"github.com/wzshiming/socks5"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

// NewClient resolves target names locally before asking the proxy to connect.
func NewClient(inner permuteproxy.Transport, _ permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	return newClient(inner, opts, true)
}

// NewClientH leaves name resolution to the proxy, as socks5h does.
func NewClientH(inner permuteproxy.Transport, _ permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	return newClient(inner, opts, false)
}

func newClient(inner permuteproxy.Transport, opts permuteproxy.Options, resolve bool) (permuteproxy.Network, error) {
	dialer := &socks5.Dialer{
		Username:  opts[KeyUsername],
		Password:  opts[KeyPassword],
		IsResolve: resolve,
		Timeout:   time.Minute,
		ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return inner.Dial(ctx, permuteproxy.Stream)
		},
	}
	return protoutils.DialNetwork(dialer.DialContext, "tcp", "tcp4", "tcp6"), nil
}

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	srv := socks5.NewServer()
	srv.ProxyDial = upstream.DialContext
	srv.ProxyListenBind = upstream.Listen
	srv.BytesPool = pool.Bytes
	if username := opts[KeyUsername]; username != "" {
		srv.Authentication = socks5.UserAuth(username, opts[KeyPassword])
	}
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		srv.Context = ctx
		return srv.Serve(ln)
	}), nil
}
