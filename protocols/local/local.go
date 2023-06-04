package local

import (
	"context"
	"net"

	"github.com/wzshiming/commandproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var LOCAL = &Local{
	Dialer:             &net.Dialer{},
	ListenConfig:       &net.ListenConfig{},
	ListenPacketConfig: &net.ListenConfig{},
	CommandDialer: permuteproxy.CommandDialFunc(func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		proxy := commandproxy.ProxyCommand(ctx, name, args...)
		// proxy.Stderr = os.Stderr
		return proxy.Stdio()
	}),
	LocalAddr: netutils.NewNetAddr("local", "local"),
}

type Local struct {
	Dialer             permuteproxy.Dialer
	ListenConfig       permuteproxy.ListenConfig
	ListenPacketConfig permuteproxy.ListenPacketConfig
	CommandDialer      permuteproxy.CommandDialer
	LocalAddr          net.Addr
}

func (l *Local) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "cmd":
		cmd := &command{l}
		return cmd.DialContext(ctx, network, address)
	case "cmd-nc":
		cmd := &command{l}
		nc := &netCatTCP{cmd}
		return nc.DialContext(ctx, network, address)
	case "cmd-nc-unix":
		cmd := &command{l}
		nc := &netCatUnix{cmd}
		return nc.DialContext(ctx, network, address)
	}

	dialer := l.Dialer
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.Dialer != nil {
		dialer = proxy.Dialer
	}
	return dialer.DialContext(ctx, network, address)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	switch network {
	case "cmd":
		cmd := &command{l}
		return cmd.Listen(ctx, network, address)
	case "cmd-nc":
		cmd := &command{l}
		nc := &netCatTCP{cmd}
		return nc.Listen(ctx, network, address)
	case "cmd-nc-unix":
		cmd := &command{l}
		nc := &netCatUnix{cmd}
		return nc.Listen(ctx, network, address)
	}

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

func (l *Local) CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error) {
	commandDialer := l.CommandDialer
	proxy, ok := permuteproxy.FromContext(ctx)
	if ok && proxy.CommandDialer != nil {
		commandDialer = proxy.CommandDialer
	}

	return commandDialer.CommandDialContext(ctx, name, args...)
}
