package netutils

import (
	"context"
	"net"
)

// CommandDialer contains options for connecting to an address with command.
type CommandDialer interface {
	CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error)
}

// CommandDialFunc type is an adapter for Dialer with command.
type CommandDialFunc func(ctx context.Context, name string, args ...string) (net.Conn, error)

// CommandDialContext calls d(ctx, name, args...)
func (d CommandDialFunc) CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error) {
	return d(ctx, name, args...)
}
