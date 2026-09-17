package local

import (
	"context"
	"net"

	winio "github.com/Microsoft/go-winio"
)

// pipe adds Windows named pipes on top of Local.
type pipe struct {
	*Local
}

func (p pipe) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "pipe" {
		return p.Local.DialContext(ctx, network, address)
	}
	return winio.DialPipeContext(ctx, address)
}

func (p pipe) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if network != "pipe" {
		return p.Local.Listen(ctx, network, address)
	}
	return winio.ListenPipe(address, &winio.PipeConfig{})
}
