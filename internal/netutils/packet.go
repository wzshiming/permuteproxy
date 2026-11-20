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
// datagram from anyone, WriteTo and ReadFrom reach and report other peers of the peer's family.
// Networks are udp4, udp6, udp bound in an IP peer's family, and unixgram at a private path Close removes.
func DialPacket(ctx context.Context, network, address string, listen ListenPacket) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &packetConn{cleanup: func() {}}
	local := ":0"
	switch network {
	case "udp", "udp4", "udp6":
		remote, err := resolveUDP(ctx, network, address)
		if err != nil {
			return nil, err
		}
		c.remote = remote
		// A dual-stack wildcard socket may get a port an IPv4 socket holds, which then takes its datagrams.
		switch {
		case network != "udp" || remote.IP == nil:
		case remote.IP.To4() != nil:
			network = "udp4"
		default:
			network = "udp6"
		}
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

// WrapPacket presents pc as the conn DialPacket returns: Write reaches remote, Read accepts any
// source, and it stays a net.PacketConn whose Close closes pc.
func WrapPacket(pc net.PacketConn, remote net.Addr) net.Conn {
	return &packetConn{PacketConn: pc, remote: remote, cleanup: func() {}}
}

// resolveUDP is net.ResolveUDPAddr with ctx reaching DNS, so a canceled dial stops waiting on it.
func resolveUDP(ctx context.Context, network, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portnum, err := net.DefaultResolver.LookupPort(ctx, network, port)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: portnum}, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	// Keep the family udp4 or udp6 asks for; udp prefers IPv4 like net.ResolveUDPAddr.
	var pick *net.IPAddr
	for i, ip := range ips {
		v4 := ip.IP.To4() != nil
		switch {
		case network == "udp4" && !v4, network == "udp6" && v4:
		case pick == nil, v4 && pick.IP.To4() == nil:
			pick = &ips[i]
		}
	}
	if pick == nil {
		return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
	}
	return &net.UDPAddr{IP: pick.IP, Port: portnum, Zone: pick.Zone}, nil
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
