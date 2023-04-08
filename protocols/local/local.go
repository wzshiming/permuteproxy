package local

import (
	"context"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var LOCAL = &Local{
	Dialer:             &net.Dialer{},
	ListenConfig:       &net.ListenConfig{},
	ListenPacketConfig: &net.ListenConfig{},
	LocalAddr:          netutils.NewNetAddr("local", "local"),
}

type Local struct {
	Dialer             permuteproxy.Dialer
	ListenConfig       permuteproxy.ListenConfig
	ListenPacketConfig permuteproxy.ListenPacketConfig
	LocalAddr          net.Addr
}

func (l *Local) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := l.Dialer
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.Dialer != nil {
		dialer = proxy.Dialer
	}

	return dialer.DialContext(ctx, network, address)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	listenConfig := l.ListenConfig
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.ListenConfig != nil {
		listenConfig = proxy.ListenConfig
	}

	return listenConfig.Listen(ctx, network, address)
}

func (l *Local) ListenPacket(ctx context.Context, network, address string) (permuteproxy.PacketConn, error) {
	listenPacketConfig := l.ListenPacketConfig
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.ListenPacketConfig != nil {
		listenPacketConfig = proxy.ListenPacketConfig
	}

	return listenPacketConfig.ListenPacket(ctx, network, address)
}
