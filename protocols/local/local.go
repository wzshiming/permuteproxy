package local

import (
	"context"
	"net"

	"github.com/go-logr/logr"
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
	logr.FromContextOrDiscard(ctx).V(1).Info("Dial", "network", network, "address", address)
	return l.Dialer.DialContext(ctx, network, address)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	logr.FromContextOrDiscard(ctx).V(1).Info("Listen", "network", network, "address", address)
	return l.ListenConfig.Listen(ctx, network, address)
}
