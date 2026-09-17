package local

import (
	"context"
	"fmt"
	"net"
)

func (l *Local) dialNetcat(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return l.dialCommand(ctx, "cmd", fmt.Sprintf("nc %s %s", host, port))
}

func (l *Local) listenNetcat(ctx context.Context, address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return l.listenCommand(ctx, "cmd", fmt.Sprintf("nc -l %s %s", host, port))
}
