package socks4

import (
	"context"
	"net"
	"time"

	"github.com/wzshiming/socks4"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	// KeyPassword is accepted for socks4://u:p@ URIs and discarded: SOCKS4 has no password.
	KeyPassword = "password"
)

func NewClient(inner permuteproxy.Transport, _ permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	dialer := &socks4.Dialer{
		Username:  opts[KeyUsername],
		IsResolve: true,
		Timeout:   time.Minute,
		ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return inner.Dial(ctx, permuteproxy.Stream)
		},
	}
	return protoutils.DialNetwork(dialer.DialContext, "tcp", "tcp4", "tcp6"), nil
}

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	srv := socks4.NewServer()
	srv.ProxyDial = upstream.DialContext
	srv.ProxyListenBind = upstream.Listen
	srv.BytesPool = pool.Bytes
	if username := opts[KeyUsername]; username != "" {
		srv.Authentication = socks4.UserAuth(username)
	}
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		srv.Context = ctx
		return srv.Serve(ln)
	}), nil
}
