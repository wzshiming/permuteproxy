package local

import (
	"context"
	"io"
	"net"
	"os/exec"
)

// Local is the process-local Network: system networking plus the cmd-* subprocess transports.
type Local struct {
	// Command starts a subprocess whose stdio carries the connection.
	Command func(ctx context.Context, name string, args ...string) (net.Conn, error)
}

var Network = &Local{Command: command}

// command runs name with its stdin fed by the conn's writes and its stdout readable from the conn.
// Closing the conn ends the command's input and returns once it has exited; ctx kills it.
func command(ctx context.Context, name string, args ...string) (net.Conn, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	local, peer := net.Pipe()
	cmd.Stdin = peer
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		io.Copy(peer, stdout)
		peer.Close()
		// Keep draining so the command can still exit after the conn stopped reading.
		io.Copy(io.Discard, stdout)
		cmd.Wait()
	}()
	return &commandConn{Conn: local, exited: exited}, nil
}

type commandConn struct {
	net.Conn
	exited <-chan struct{}
}

func (c *commandConn) Close() error {
	err := c.Conn.Close()
	<-c.exited
	return err
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
