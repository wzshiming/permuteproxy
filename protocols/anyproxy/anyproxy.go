package anyproxy

import (
	"context"
	"net"

	"github.com/wzshiming/anyproxy"

	_ "github.com/wzshiming/anyproxy/proxies/httpproxy"
	_ "github.com/wzshiming/anyproxy/proxies/socks4"
	_ "github.com/wzshiming/anyproxy/proxies/socks5"
	_ "github.com/wzshiming/anyproxy/proxies/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/protocols"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

type runner struct {
	listener permuteproxy.Listener
	server   *anyproxy.AnyProxy
}

func NewAnyProxyRunner(listener permuteproxy.Listener, metadata permuteproxy.Metadata) (permuteproxy.Runner, error) {
	protos := []string{
		"http",
		"socks4",
		"socks5",
		"ssh",
	}

	addrs := make([]string, 0, len(protos))
	for _, proto := range protos {
		addrs = append(addrs, protocols.EncodeURLWithMetadata(proto, "localhost", metadata, KeyUsername, KeyPassword))
	}

	server, err := anyproxy.NewAnyProxy(context.Background(), addrs, &anyproxy.Config{
		BytesPool:    pool.Bytes,
		ListenConfig: &wrapper{listener},
	})
	if err != nil {
		return nil, err
	}
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

type wrapper struct {
	listener permuteproxy.Listener
}

func (w *wrapper) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return w.listener, nil
}
