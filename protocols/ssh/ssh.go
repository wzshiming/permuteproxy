package ssh

import (
	"context"

	"github.com/wzshiming/permuteproxy/protocols"
	"github.com/wzshiming/sshproxy"
)

// NewSSHDialer ssh proxy dialer
func NewSSHDialer(d protocols.Dialer) (protocols.Dialer, error) {
	return &dialer{d}, nil
}

type dialer struct {
	dialer protocols.Dialer
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (protocols.Conn, error) {
	dialer, err := sshproxy.NewDialer("ssh://localhost")
	if err != nil {
		return nil, err
	}
	dialer.ProxyDial = d.dialer.DialContext
	return dialer.DialContext(ctx, network, address)
}

type runner struct {
	listener protocols.Listener
}

func NewSSHRunner(listener protocols.Listener) protocols.Runner {
	return &runner{
		listener: listener,
	}
}

func (r *runner) Run(ctx context.Context) error {
	s, err := sshproxy.NewSimpleServer("ssh://localhost")
	if err != nil {
		return err
	}
	s.Listener = r.listener
	return s.Server.Serve(r.listener)
}

func (r *runner) Close() error {
	return r.listener.Close()
}
