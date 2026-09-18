package socks5

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/wzshiming/socks5"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

// NewClient resolves target names locally before asking the proxy to connect.
func NewClient(inner permuteproxy.Transport, base permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	return newClient(inner, base, opts, true)
}

// NewClientH leaves name resolution to the proxy, as socks5h does.
func NewClientH(inner permuteproxy.Transport, base permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	return newClient(inner, base, opts, false)
}

func newClient(inner permuteproxy.Transport, base permuteproxy.Network, opts permuteproxy.Options, resolve bool) (permuteproxy.Network, error) {
	c := &client{inner: inner, base: base, dialer: socks5.Dialer{
		Username:  opts[KeyUsername],
		Password:  opts[KeyPassword],
		IsResolve: resolve,
		Timeout:   time.Minute,
	}}
	c.dialer.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return inner.Dial(ctx, permuteproxy.Stream)
	}
	return c, nil
}

// client connects through inner and opens the sockets of its UDP associations through base.
type client struct {
	inner  permuteproxy.Transport
	base   permuteproxy.Network
	dialer socks5.Dialer
}

func (c *client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return c.dialer.DialContext(ctx, network, address)
	case "udp", "udp4", "udp6":
		a, err := c.associate(ctx, "udp", ":0", address)
		if err != nil {
			return nil, err
		}
		remote := a.udp.RemoteAddr()
		// The library parses the target as an IP only; socks5h keeps the name for the proxy.
		if u, ok := remote.(*net.UDPAddr); ok && u.IP == nil {
			remote = netutils.NewNetAddr("udp", address)
		}
		return netutils.WrapPacket(a, remote), nil
	}
	return nil, fmt.Errorf("dial %s: %w", network, permuteproxy.ErrUnsupported)
}

func (c *client) Listen(_ context.Context, network, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("listen %s: %w", network, permuteproxy.ErrUnsupported)
}

// ListenPacket opens an association whose socket is bound at address; WriteTo reaches any target.
func (c *client) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		a, err := c.associate(ctx, network, address, ":0")
		if err != nil {
			return nil, err
		}
		return a, nil
	}
	return nil, fmt.Errorf("listen packet %s: %w", network, permuteproxy.ErrUnsupported)
}

// associate performs the UDP ASSOCIATE handshake with the socket bound through base at local.
func (c *client) associate(ctx context.Context, network, local, target string) (*association, error) {
	a := &association{}
	d := c.dialer
	d.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := c.inner.Dial(ctx, permuteproxy.Stream)
		if err != nil {
			return nil, err
		}
		if err := a.adopt(conn, nil); err != nil {
			return nil, err
		}
		return conn, nil
	}
	d.ProxyPacketDial = func(ctx context.Context, _, _ string) (net.PacketConn, error) {
		pc, err := c.base.ListenPacket(ctx, network, local)
		if err != nil {
			return nil, err
		}
		if err := a.adopt(nil, pc); err != nil {
			return nil, err
		}
		return socket{pc, a}, nil
	}
	// The library only turns a context deadline into conn deadlines; closing ends a canceled handshake.
	stop := context.AfterFunc(ctx, func() { a.Close() })
	conn, err := d.DialContext(ctx, "udp", target)
	if !stop() {
		a.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		a.Close()
		return nil, err
	}
	a.udp = conn.(*socks5.UDPConn)
	return a, nil
}

// association is one UDP association: the control conn keeps it open on the proxy, the socket
// carries the datagrams with their socks5 headers, and Close ends both exactly once.
type association struct {
	mu      sync.Mutex
	closed  bool
	control net.Conn
	socket  net.PacketConn
	udp     *socks5.UDPConn
}

// adopt keeps a conn opened during the handshake, closing it at once if Close already happened.
func (a *association) adopt(control net.Conn, socket net.PacketConn) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		if control != nil {
			control.Close()
		}
		if socket != nil {
			socket.Close()
		}
		return net.ErrClosed
	}
	if control != nil {
		a.control = control
	}
	if socket != nil {
		a.socket = socket
	}
	return nil
}

func (a *association) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	var err error
	if a.control != nil {
		err = a.control.Close()
	}
	if a.socket != nil {
		if e := a.socket.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (a *association) ReadFrom(b []byte) (int, net.Addr, error) {
	return a.udp.ReadFrom(b)
}

func (a *association) WriteTo(b []byte, addr net.Addr) (int, error) {
	return a.udp.WriteTo(b, addr)
}

func (a *association) LocalAddr() net.Addr {
	return a.socket.LocalAddr()
}

func (a *association) SetDeadline(t time.Time) error {
	return a.socket.SetDeadline(t)
}

func (a *association) SetReadDeadline(t time.Time) error {
	return a.socket.SetReadDeadline(t)
}

func (a *association) SetWriteDeadline(t time.Time) error {
	return a.socket.SetWriteDeadline(t)
}

// socket is the packet conn the library holds; it closes it when the control conn ends, which
// must end the whole association.
type socket struct {
	net.PacketConn
	a *association
}

func (s socket) Close() error {
	return s.a.Close()
}

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	srv := socks5.NewServer()
	srv.ProxyDial = upstream.DialContext
	srv.ProxyListenBind = upstream.Listen
	srv.ProxyListenPacket = listenRelay
	srv.ProxyOutgoingListenPacket = upstream.ListenPacket
	srv.PacketForwardAddress = relayAddress
	srv.BytesPool = pool.Bytes
	if username := opts[KeyUsername]; username != "" {
		srv.Authentication = socks5.UserAuth(username, opts[KeyPassword])
	}
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		srv.Context = ctx
		return srv.Serve(ln)
	}), nil
}

// listenRelay binds the client-facing relay socket locally on a free port; the address the
// library passes is the client's DST.ADDR, which is not a bind request.
func listenRelay(ctx context.Context, network, _ string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, ":0")
}

// relayAddress advertises the relay port at the IP the client reached the control conn on; a
// carrier without one gets the relay's own IP, or its family's loopback when it is unspecified.
func relayAddress(_ context.Context, _ string, relay net.PacketConn, control net.Conn) (net.IP, int, error) {
	local, ok := relay.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("relay bound to %v, want a udp address", relay.LocalAddr())
	}
	if tcp, ok := control.LocalAddr().(*net.TCPAddr); ok {
		return tcp.IP, local.Port, nil
	}
	ip := local.IP
	if ip.IsUnspecified() {
		ip = net.IPv6loopback
		if local.IP.To4() != nil {
			ip = net.IPv4(127, 0, 0, 1)
		}
	}
	return ip, local.Port, nil
}
