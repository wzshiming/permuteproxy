package http

import (
	"context"
	"time"

	"github.com/wzshiming/httpproxy"
	"github.com/wzshiming/permuteproxy/protocols"
)

// NewHttpDialer http proxy dialer
func NewHttpDialer(d protocols.Dialer) (protocols.Dialer, error) {
	return &dialer{d}, nil
}

type dialer struct {
	dialer protocols.Dialer
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (protocols.Conn, error) {
	dialer := &httpproxy.Dialer{
		ProxyDial: d.dialer.DialContext,
		Timeout:   10 * time.Second,
	}
	return dialer.DialContext(ctx, network, address)
}

type runner struct {
	listener protocols.Listener
}

func NewHttpRunner(listener protocols.Listener) protocols.Runner {
	return &runner{
		listener: listener,
	}
}

func (r *runner) Run(ctx context.Context) error {
	s, err := httpproxy.NewSimpleServer("http://localhost")
	if err != nil {
		return err
	}
	r.listener = httpproxy.NewListenerCompatibilityReadDeadline(r.listener)
	return s.Server.Serve(r.listener)
}

func (r *runner) Close() error {
	return r.listener.Close()
}
