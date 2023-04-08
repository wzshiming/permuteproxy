package shadowsocks

import (
	"context"

	_ "github.com/wzshiming/shadowsocks/init"

	"github.com/wzshiming/shadowsocks"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/protocols"
)

const (
	KeyUsername = "encrypto"
	KeyPassword = "password"
)

// NewShadowsocksDialer shadowsocks proxy dialer
func NewShadowsocksDialer(ctx context.Context, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	proxy, ok := permuteproxy.FromContext(ctx)
	if !ok || proxy.Dialer == nil {
		return nil, permuteproxy.ErrNoProxy
	}

	if metadata.Get(KeyUsername) == "" {
		metadata.Set(KeyUsername, "dummy")
	}
	u := protocols.EncodeURLWithMetadata("shadowsocks", "localhost", metadata, KeyUsername, KeyPassword)
	dialer, err := shadowsocks.NewDialer(u)
	if err != nil {
		return nil, err
	}

	dialer.ProxyDial = proxy.Dialer.DialContext
	return dialer, nil
}

type runner struct {
	listener permuteproxy.Listener
	server   *shadowsocks.SimpleServer
}

func NewShadowsocksRunner(listener permuteproxy.Listener, metadata permuteproxy.Metadata) (permuteproxy.Runner, error) {
	if metadata.Get(KeyUsername) == "" {
		metadata.Set(KeyUsername, "dummy")
	}
	u := protocols.EncodeURLWithMetadata("shadowsocks", "localhost", metadata, KeyUsername, KeyPassword)
	server, err := shadowsocks.NewSimpleServer(u)
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
