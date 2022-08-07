package socks4

import (
	"context"
	"time"

	"github.com/wzshiming/permuteproxy/protocols"
	"github.com/wzshiming/socks4"
)

// NewSocks4Dialer http proxy dialer
func NewSocks4Dialer(d protocols.Dialer) (protocols.Dialer, error) {
	return &dialer{d}, nil
}

type dialer struct {
	dialer protocols.Dialer
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (protocols.Conn, error) {
	dialer := &socks4.Dialer{
		ProxyDial: d.dialer.DialContext,
		Timeout:   10 * time.Second,
	}
	return dialer.DialContext(ctx, network, address)
}

type runner struct {
	listener protocols.Listener
}

func NewSocks4Runner(listener protocols.Listener) protocols.Runner {
	return &runner{
		listener: listener,
	}
}

func (r *runner) Run(ctx context.Context) error {
	s, err := socks4.NewSimpleServer("socks4://localhost")
	if err != nil {
		return err
	}
	s.Listener = r.listener
	return s.Server.Serve(r.listener)
}

func (r *runner) Close() error {
	return r.listener.Close()
}
