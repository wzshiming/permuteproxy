package socks4

import (
	"context"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/protocols"
	"github.com/wzshiming/socks4"
)

const (
	KeyUsername = "username"
)

// NewSocks4Dialer socks4 proxy dialer
func NewSocks4Dialer(d permuteproxy.Dialer, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	u := protocols.EncodeURLWithMetadata("socks4", "localhost", metadata, KeyUsername, "")
	dialer, err := socks4.NewDialer(u)
	if err != nil {
		return nil, err
	}
	dialer.ProxyDial = d.DialContext
	return dialer, nil
}

type runner struct {
	listener permuteproxy.Listener
	server   *socks4.SimpleServer
}

func NewSocks4Runner(listener permuteproxy.Listener, metadata permuteproxy.Metadata) (permuteproxy.Runner, error) {
	u := protocols.EncodeURLWithMetadata("socks4", "localhost", metadata, KeyUsername, "")
	server, err := socks4.NewSimpleServer(u)
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
