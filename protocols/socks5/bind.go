package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/clientutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// The library's listener learns neither the address the proxy bound nor when to stop, so BIND is spoken here (RFC 1928, RFC 1929).
const (
	version     = 5
	authVersion = 1
	cmdBind     = 2
	methodNone  = 0
	methodUser  = 2
	atypIPv4    = 1
	atypName    = 3
	atypIPv6    = 4
)

// replies names the REP codes of RFC 1928.
var replies = []string{
	"succeeded", "general SOCKS server failure", "connection not allowed by ruleset", "network unreachable", "host unreachable",
	"connection refused", "TTL expired", "command not supported", "address type not supported",
}

// listen asks the proxy to listen at address with BIND; an empty host is the IPv4 wildcard.
func (c *client) listen(ctx context.Context, inner permuteproxy.Transport, _, address string) (net.Listener, error) {
	return clientutils.ListenBind(ctx, address, func(ctx context.Context, address string) (net.Conn, net.Addr, error) {
		request, err := c.bindRequest(ctx, address)
		if err != nil {
			return nil, nil, err
		}
		conn, err := inner.Dial(ctx, permuteproxy.Stream)
		if err != nil {
			return nil, nil, err
		}
		var bound net.Addr
		err = clientutils.Handshake(ctx, conn, c.dialer.Timeout, func() error {
			if err := c.authenticate(conn); err != nil {
				return err
			}
			if _, err := conn.Write(request); err != nil {
				return err
			}
			bound, err = readReply(conn)
			return err
		})
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("socks5: bind %s: %w", address, err)
		}
		return conn, bound, nil
	}, readReply)
}

// bindRequest is the BIND request for address, its name resolved as a dial's is.
func (c *client) bindRequest(ctx context.Context, address string) ([]byte, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("socks5: bind %s: port is not a number from 0 to 65535", address)
	}
	if host, err = c.lookup(ctx, host); err != nil {
		return nil, err
	}
	b := []byte{version, cmdBind, 0}
	switch ip := net.ParseIP(host); {
	case host == "":
		b = append(b, atypIPv4, 0, 0, 0, 0)
	case ip.To4() != nil:
		b = append(append(b, atypIPv4), ip.To4()...)
	case ip != nil:
		b = append(append(b, atypIPv6), ip...)
	case len(host) > 255:
		return nil, fmt.Errorf("socks5: bind %s: host of %d bytes is longer than 255", address, len(host))
	default:
		b = append(append(b, atypName, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(portnum)), nil
}

// authenticate offers no authentication and, with a username, username/password, and performs the one the proxy picks.
func (c *client) authenticate(conn net.Conn) error {
	username, password := c.dialer.Username, c.dialer.Password
	methods := []byte{version, 1, methodNone}
	if username != "" {
		methods = []byte{version, 2, methodNone, methodUser}
	}
	if _, err := conn.Write(methods); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	switch {
	case reply[0] != version:
		return fmt.Errorf("unexpected protocol version %d", reply[0])
	case reply[1] == methodNone:
		return nil
	case reply[1] != methodUser || username == "":
		return fmt.Errorf("no acceptable authentication method, proxy answered %d", reply[1])
	case len(username) > 255 || password == "" || len(password) > 255:
		return errors.New("username or password is empty or longer than 255 bytes")
	}
	auth := append([]byte{authVersion, byte(len(username))}, username...)
	auth = append(append(auth, byte(len(password))), password...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != authVersion || reply[1] != 0 {
		return errors.New("username/password authentication failed")
	}
	return nil
}

// readReply reads one reply and returns its address: what the proxy bound in BIND's first reply, the peer it accepted in the second.
func readReply(conn net.Conn) (net.Addr, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	switch {
	case head[0] != version:
		return nil, fmt.Errorf("unexpected protocol version %d", head[0])
	case head[1] != 0 && int(head[1]) < len(replies):
		return nil, errors.New(replies[head[1]])
	case head[1] != 0:
		return nil, fmt.Errorf("reply code %d", head[1])
	}
	size := 0
	switch head[3] {
	case atypIPv4:
		size = net.IPv4len
	case atypIPv6:
		size = net.IPv6len
	case atypName:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return nil, err
		}
		size = int(n[0])
	default:
		return nil, fmt.Errorf("unknown address type %d", head[3])
	}
	b := make([]byte, size+2)
	if _, err := io.ReadFull(conn, b); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(b[size:]))
	if head[3] == atypName {
		return netutils.NewNetAddr("tcp", net.JoinHostPort(string(b[:size]), strconv.Itoa(port))), nil
	}
	return &net.TCPAddr{IP: net.IP(b[:size]), Port: port}, nil
}
