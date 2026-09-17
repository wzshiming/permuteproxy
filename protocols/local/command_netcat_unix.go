package local

import (
	"context"
	"fmt"
	"net"
)

func (l *Local) dialNetcatUnix(ctx context.Context, address string) (net.Conn, error) {
	return l.dialCommand(ctx, "cmd", fmt.Sprintf("nc -U %s", address))
}

func (l *Local) listenNetcatUnix(ctx context.Context, address string) (net.Listener, error) {
	return l.listenCommand(ctx, "cmd", fmt.Sprintf("nc -Ul %s", address))
}
