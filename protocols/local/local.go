package local

import (
	"context"
	"net"

	"github.com/wzshiming/commandproxy"
)

// Local is the process-local Network: system networking plus the cmd-* subprocess transports.
type Local struct {
	// Command starts a subprocess whose stdio carries the connection.
	Command func(ctx context.Context, name string, args ...string) (net.Conn, error)
}

var Network = &Local{Command: command}

func command(ctx context.Context, name string, args ...string) (net.Conn, error) {
	return commandproxy.ProxyCommand(ctx, name, args...).Stdio()
}

func (l *Local) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "cmd":
		return l.dialCommand(ctx, network, address)
	case "cmd-nc":
		return l.dialNetcat(ctx, address)
	case "cmd-nc-unix":
		return l.dialNetcatUnix(ctx, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (l *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	switch network {
	case "cmd":
		return l.listenCommand(ctx, network, address)
	case "cmd-nc":
		return l.listenNetcat(ctx, address)
	case "cmd-nc-unix":
		return l.listenNetcatUnix(ctx, address)
	}
	return (&net.ListenConfig{}).Listen(ctx, network, address)
}

func (l *Local) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}
