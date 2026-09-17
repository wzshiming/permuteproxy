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

func NewClient(inner permuteproxy.Transport, _ permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	dialer := &httpproxy.Dialer{
		Userinfo: protoutils.Userinfo(opts, KeyUsername, KeyPassword),
		Timeout:  time.Minute,
		ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return inner.Dial(ctx, permuteproxy.Stream)
		},
	}
	return protoutils.DialNetwork(dialer.DialContext, "tcp", "tcp4", "tcp6"), nil
}

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	handler := &httpproxy.ProxyHandler{
		ProxyDial: upstream.DialContext,
		BytesPool: pool.Bytes,
	}
	if username := opts[KeyUsername]; username != "" {
		handler.Authentication = httpproxy.BasicAuth(username, opts[KeyPassword])
	}
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		srv := &http.Server{
			Handler:     handler,
			BaseContext: func(net.Listener) context.Context { return ctx },
		}
		defer srv.Close()
		return srv.Serve(httpproxy.NewListenerCompatibilityReadDeadline(ln))
	}), nil
}
