package netutils

import (
	"fmt"
	"net"
	"sync"
)

// StreamPacket presents conn as best-effort datagrams with peer, one conn.Read or conn.Write each.
func StreamPacket(conn net.Conn, peer net.Addr) net.Conn {
	return &streamPacket{Conn: conn, peer: peer}
}

type streamPacket struct {
	net.Conn
	peer net.Addr
	once sync.Once
}

func (c *streamPacket) RemoteAddr() net.Addr {
	return c.peer
}

func (c *streamPacket) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

func (c *streamPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, c.peer, err
}

func (c *streamPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != c.peer.String() {
		return 0, fmt.Errorf("write to %v: the stream reaches only %v", addr, c.peer)
	}
	return c.Conn.Write(b)
}
