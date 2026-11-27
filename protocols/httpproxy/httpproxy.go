package httpproxy

import (
	"context"
	"net"
	"time"

	"github.com/wzshiming/httpproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	userinfo := protoutils.Userinfo(opts, KeyUsername, KeyPassword)
	return &permuteproxy.ClientFuncs{
		Dial: func(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
			dialer := &httpproxy.Dialer{
				Userinfo: userinfo,
				Timeout:  time.Minute,
				ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return inner.Dial(ctx, permuteproxy.Stream)
				},
			}
			return dialer.DialContext(ctx, network, address)
		},
	}, nil
}

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	var auth httpproxy.Authentication
	if username := opts[KeyUsername]; username != "" {
		auth = httpproxy.BasicAuth(username, opts[KeyPassword])
	}
	return &permuteproxy.ServerFuncs{
		Serve: func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
			srv := httpproxy.NewServer()
			srv.Context = ctx
			srv.ProxyDial = upstream.DialContext
			srv.Authentication = auth
			srv.BytesPool = netutils.Buffers
			return srv.Serve(ln)
		},
	}, nil
}
