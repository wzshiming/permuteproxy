package netutils

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// ListenPacket is the Network.ListenPacket shape DialPacket binds its local socket through.
type ListenPacket func(ctx context.Context, network, address string) (net.PacketConn, error)

// DialPacket opens an unconnected datagram socket through listen with address as its default peer.
// The conn is also a net.PacketConn: Write sends one datagram to the peer and Read yields the next
// datagram from anyone, WriteTo and ReadFrom reach and report other peers. Networks are udp, udp4,
// udp6 and unixgram; unixgram binds a private socket path that Close removes.
func DialPacket(ctx context.Context, network, address string, listen ListenPacket) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &packetConn{cleanup: func() {}}
	local := ":0"
	switch network {
	case "udp", "udp4", "udp6":
		remote, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		c.remote = remote
	case "unixgram":
		if address == "" {
			return nil, fmt.Errorf("dial %s: missing address", network)
		}
		dir, err := os.MkdirTemp("", "pp")
		if err != nil {
			return nil, err
		}
		c.cleanup = func() { os.RemoveAll(dir) }
		c.remote = &net.UnixAddr{Name: address, Net: network}
		local = filepath.Join(dir, "s")
	default:
		return nil, fmt.Errorf("dial %s: not a datagram network", network)
	}
	pc, err := listen(ctx, network, local)
	if err != nil {
		c.cleanup()
		return nil, err
	}
	c.PacketConn = pc
	if err := ctx.Err(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

type packetConn struct {
	net.PacketConn
	remote  net.Addr
	cleanup func()
	once    sync.Once
}

func (c *packetConn) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *packetConn) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.remote)
}

func (c *packetConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *packetConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.PacketConn.Close()
		c.cleanup()
	})
	return err
}
