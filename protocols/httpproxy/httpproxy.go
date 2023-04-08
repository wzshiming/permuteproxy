package httpproxy

import (
	"context"

	"github.com/wzshiming/httpproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/protocols"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

// NewHttpProxyDialer http proxy dialer
func NewHttpProxyDialer(ctx context.Context, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	proxy, ok := permuteproxy.FromContext(ctx)
	if !ok || proxy.Dialer == nil {
		return nil, permuteproxy.ErrNoProxy
	}

	u := protocols.EncodeURLWithMetadata("http", "localhost", metadata, KeyUsername, KeyPassword)
	dialer, err := httpproxy.NewDialer(u)
	if err != nil {
		return nil, err
	}

	dialer.ProxyDial = proxy.Dialer.DialContext
	return dialer, nil
}

type runner struct {
	listener permuteproxy.Listener
	server   *httpproxy.SimpleServer
}

func NewHttpProxyRunner(listener permuteproxy.Listener, metadata permuteproxy.Metadata) (permuteproxy.Runner, error) {
	u := protocols.EncodeURLWithMetadata("http", "localhost", metadata, KeyUsername, KeyPassword)
	server, err := httpproxy.NewSimpleServer(u)
	if err != nil {
		return nil, err
	}
	server.BytesPool = pool.Bytes
	server.Listener = httpproxy.NewListenerCompatibilityReadDeadline(listener)
	return &runner{
		server:   server,
		listener: listener,
	}, nil
}

func (r *runner) Run(ctx context.Context) error {
	return r.server.Run(ctx)
}

func (r *runner) Close() error {
	return r.listener.Close()
}
