package socks5

import (
	"context"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/protocols"
	"github.com/wzshiming/socks5"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

// NewSocks5Dialer socks5 proxy dialer
func NewSocks5Dialer(d permuteproxy.Dialer, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	u := protocols.EncodeURLWithMetadata("socks5", "localhost", metadata, KeyUsername, KeyPassword)
	dialer, err := socks5.NewDialer(u)
	if err != nil {
		return nil, err
	}
	dialer.ProxyDial = d.DialContext
	return dialer, nil
}

type runner struct {
	listener permuteproxy.Listener
	server   *socks5.SimpleServer
}

func NewSocks5Runner(listener permuteproxy.Listener, metadata permuteproxy.Metadata) (permuteproxy.Runner, error) {
	u := protocols.EncodeURLWithMetadata("socks5", "localhost", metadata, KeyUsername, KeyPassword)
	server, err := socks5.NewSimpleServer(u)
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
