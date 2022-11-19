package local

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var LOCAL = &Local{
	Dialer:       &net.Dialer{},
	ListenConfig: &net.ListenConfig{},
	LocalAddr:    netutils.NewNetAddr("local", "local"),
}

type Local struct {
	Dialer       permuteproxy.Dialer
	ListenConfig permuteproxy.ListenConfig
	LocalAddr    net.Addr
}

func (l *Local) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return l.Dialer.DialContext(ctx, network, address)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return l.ListenConfig.Listen(ctx, network, address)
}
