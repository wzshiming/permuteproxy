package httpproxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/wzshiming/httpproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
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
			srv := &http.Server{
				Handler: &httpproxy.ProxyHandler{
					ProxyDial:      upstream.DialContext,
					Authentication: auth,
					BytesPool:      pool.Bytes,
				},
				BaseContext: func(net.Listener) context.Context { return ctx },
			}
			defer srv.Close()
			return srv.Serve(httpproxy.NewListenerCompatibilityReadDeadline(ln))
		},
	}, nil
}
