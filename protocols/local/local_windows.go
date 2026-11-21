package local

import (
	"context"
	"net"

	winio "github.com/Microsoft/go-winio"
)

func dialPipe(ctx context.Context, _, address string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, address)
}

func listenPipe(_ context.Context, _, address string) (net.Listener, error) {
	return winio.ListenPipe(address, &winio.PipeConfig{})
}
