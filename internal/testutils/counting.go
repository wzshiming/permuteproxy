package testutils

import (
	"context"
	"net"
	"sync/atomic"
)

// CountingNetwork fails every call with net.ErrClosed and counts the calls.
type CountingNetwork struct{ Calls atomic.Int32 }

func (n *CountingNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	n.Calls.Add(1)
	return nil, net.ErrClosed
}

func (n *CountingNetwork) Listen(context.Context, string, string) (net.Listener, error) {
	n.Calls.Add(1)
	return nil, net.ErrClosed
}

func (n *CountingNetwork) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	n.Calls.Add(1)
	return nil, net.ErrClosed
}

// CountingConn counts its Close calls in Closes.
type CountingConn struct {
	net.Conn
	Closes *atomic.Int32
}

func (c CountingConn) Close() error {
	c.Closes.Add(1)
	return c.Conn.Close()
}
