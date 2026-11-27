package socks4

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// The library's listener learns neither the address the proxy bound nor when to stop, so BIND is spoken here.
const (
	version = 4
	cmdBind = 2
	granted = 90
)

// listenBind asks the proxy to listen at address with BIND; an empty host is the wildcard, a name is resolved here to IPv4 as a dial's is.
func listenBind(ctx context.Context, inner permuteproxy.Transport, username, address string) (net.Listener, error) {
	return netutils.ListenBind(ctx, address, func(ctx context.Context, address string) (net.Conn, net.Addr, error) {
		request, err := bindRequest(ctx, username, address)
		if err != nil {
			return nil, nil, err
		}
		conn, err := inner.Dial(ctx, permuteproxy.Stream)
		if err != nil {
			return nil, nil, err
		}
		var bound net.Addr
		err = netutils.Handshake(ctx, conn, time.Minute, func() error {
			if _, err := conn.Write(request); err != nil {
				return err
			}
			bound, err = readReply(conn)
			return err
		})
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("socks4: bind %s: %w", address, err)
		}
		return conn, bound, nil
	}, readReply)
}

func bindRequest(ctx context.Context, username, address string) ([]byte, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("socks4: bind %s: port is not a number from 0 to 65535", address)
	}
	ip := net.IPv4zero
	if host != "" {
		if ip = net.ParseIP(host); ip == nil {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil {
				return nil, err
			}
			ip = ips[0]
		}
	}
	if ip = ip.To4(); ip == nil {
		return nil, fmt.Errorf("socks4: bind %s: not an IPv4 address", address)
	}
	if strings.IndexByte(username, 0) >= 0 {
		return nil, fmt.Errorf("socks4: bind %s: username has a NUL byte", address)
	}
	b := binary.BigEndian.AppendUint16([]byte{version, cmdBind}, uint16(portnum))
	return append(append(append(b, ip...), username...), 0), nil
}

// readReply reads one reply and returns its address: what the proxy bound in BIND's first reply, the peer it accepted in the second.
func readReply(conn net.Conn) (net.Addr, error) {
	var b [8]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return nil, err
	}
	switch {
	case b[0] != 0:
		return nil, fmt.Errorf("unexpected reply version %d", b[0])
	case b[1] != granted:
		return nil, fmt.Errorf("request rejected or failed, reply code %d", b[1])
	}
	return &net.TCPAddr{IP: net.IP(b[4:8]), Port: int(binary.BigEndian.Uint16(b[2:4]))}, nil
}
