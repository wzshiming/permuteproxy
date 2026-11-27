package socks4

import (
	"context"
	"net"
	"time"

	"github.com/wzshiming/socks4"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/serverutils"
)

const (
	KeyUsername = "username"
	// KeyPassword is accepted for socks4://u:p@ URIs and discarded: SOCKS4 has no password.
	KeyPassword = "password"
)

func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	username := opts[KeyUsername]
	return &permuteproxy.ClientFuncs{
		Dial: func(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
			dialer := &socks4.Dialer{
				Username:  username,
				IsResolve: true,
				Timeout:   time.Minute,
				ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return inner.Dial(ctx, permuteproxy.Stream)
				},
			}
			return dialer.DialContext(ctx, network, address)
		},
		Listen: func(ctx context.Context, inner permuteproxy.Transport, _, address string) (net.Listener, error) {
			return listenBind(ctx, inner, username, address)
		},
	}, nil
}

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	username := opts[KeyUsername]
	return &permuteproxy.ServerFuncs{
		Serve: func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
			owned := serverutils.NewListeners(upstream.Listen)
			defer owned.Close()
			srv := socks4.NewServer()
			srv.Context = ctx
			srv.ProxyDial = upstream.DialContext
			srv.ProxyListenBind = owned.Listen
			srv.BytesPool = pool.Bytes
			if username != "" {
				srv.Authentication = socks4.UserAuth(username)
			}
			return srv.Serve(ln)
		},
	}, nil
}
