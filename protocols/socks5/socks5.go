package socks5

import (
	"context"
	"time"

	"github.com/wzshiming/permuteproxy/protocols"
	"github.com/wzshiming/socks5"
)

// NewSocks5Dialer http proxy dialer
func NewSocks5Dialer(d protocols.Dialer) (protocols.Dialer, error) {
	return &dialer{d}, nil
}

type dialer struct {
	dialer protocols.Dialer
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (protocols.Conn, error) {
	dialer := &socks5.Dialer{
		ProxyDial: d.dialer.DialContext,
		Timeout:   10 * time.Second,
	}
	return dialer.DialContext(ctx, network, address)
}

type runner struct {
	listener protocols.Listener
}

func NewSocks5Runner(listener protocols.Listener) protocols.Runner {
	return &runner{
		listener: listener,
	}
}

func (r *runner) Run(ctx context.Context) error {
	s, err := socks5.NewSimpleServer("socks5://localhost")
	if err != nil {
		return err
	}
	s.Listener = r.listener
	return s.Server.Serve(r.listener)
}

func (r *runner) Close() error {
	return r.listener.Close()
}
