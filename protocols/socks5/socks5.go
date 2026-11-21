package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/wzshiming/socks5"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/pool"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

// NewClient resolves target names locally before asking the proxy to connect.
func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	return newClient(opts, true)
}

// NewClientH leaves name resolution to the proxy, as socks5h does.
func NewClientH(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	return newClient(opts, false)
}

func newClient(opts permuteproxy.Options, resolve bool) (*permuteproxy.ClientFuncs, error) {
	c := &client{dialer: socks5.Dialer{
		Username:  opts[KeyUsername],
		Password:  opts[KeyPassword],
		IsResolve: resolve,
		Timeout:   time.Minute,
	}}
	return &permuteproxy.ClientFuncs{Dial: c.dial, ListenPacket: c.associate, Peer: c.peer}, nil
}

// client takes its control conns from inner and binds the sockets of its UDP associations through local.
type client struct {
	dialer socks5.Dialer
}

func (c *client) dial(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
	d := c.dialer
	d.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return inner.Dial(ctx, permuteproxy.Stream)
	}
	return d.DialContext(ctx, network, address)
}

// peer is the default target the library's udp dial kept, a name resolved here first for socks5.
func (c *client) peer(ctx context.Context, _, address string) (net.Addr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if c.dialer.IsResolve && host != "" && net.ParseIP(host) == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			if ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host); err != nil {
				return nil, err
			}
		}
		host = ips[0].String()
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	if portnum < 0 || portnum > 0xffff {
		return nil, errors.New("port number out of range " + port)
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: portnum}, nil
	}
	// The library parses the target as an IP only; socks5h keeps the name for the proxy.
	return netutils.NewNetAddr("udp", address), nil
}

// associate performs the UDP ASSOCIATE handshake with its socket bound through local at address in the
// control conn's family; WriteTo reaches any target.
func (c *client) associate(ctx context.Context, inner permuteproxy.Transport, local permuteproxy.Network, network, address string) (net.PacketConn, error) {
	a := &association{}
	d := c.dialer
	d.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := inner.Dial(ctx, permuteproxy.Stream)
		if err != nil {
			return nil, err
		}
		if err := a.adopt(conn, nil); err != nil {
			return nil, err
		}
		return conn, nil
	}
	d.ProxyPacketDial = func(ctx context.Context, _, _ string) (net.PacketConn, error) {
		pc, err := local.ListenPacket(ctx, udpFamily(a.control.RemoteAddr(), network), address)
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
	conn, err := d.DialContext(ctx, "udp", ":0")
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

// udpFamily is udp4 or udp6 after a tcp address's IP, the family of a relay advertised at it, else network.
func udpFamily(addr net.Addr, network string) string {
	tcp, ok := addr.(*net.TCPAddr)
	switch {
	case !ok || tcp.IP == nil:
		return network
	case tcp.IP.To4() != nil:
		return "udp4"
	}
	return "udp6"
}

// association is one UDP association: the control conn keeps it open on the proxy, the socket
// carries the datagrams with their socks5 headers, and Close ends both exactly once. The library
// conn assembles and parses datagrams in one read and one write buffer, so ReadFrom and WriteTo are
// serialized independently; Close and the deadlines bypass the buffers and take neither lock.
type association struct {
	mu      sync.Mutex
	closed  bool
	control net.Conn
	socket  net.PacketConn
	udp     *socks5.UDPConn
	readMu  sync.Mutex
	writeMu sync.Mutex
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

// ReadFrom skips datagrams the library rejects, from another source or without a socks5 header,
// and returns only the socket's own errors, which socket tags since the library returns them raw.
func (a *association) ReadFrom(b []byte) (int, net.Addr, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	for {
		n, addr, err := a.udp.ReadFrom(b)
		if err == nil {
			return n, addr, nil
		}
		var re readError
		if errors.As(err, &re) {
			return 0, nil, re.error
		}
	}
}

func (a *association) WriteTo(b []byte, addr net.Addr) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
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

func (s socket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, readError{err}
	}
	return n, addr, nil
}

// readError marks an error of the socket itself, as opposed to one about a datagram's content.
type readError struct{ error }

func (e readError) Unwrap() error { return e.error }

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	return &permuteproxy.ServerFuncs{Serve: func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
		owned := &listeners{listen: upstream.Listen}
		defer owned.Close()
		srv := socks5.NewServer()
		srv.Context = ctx
		srv.ProxyDial = upstream.DialContext
		srv.ProxyListenBind = owned.Listen
		srv.ProxyListenPacket = listenRelay
		srv.ProxyOutgoingListenPacket = upstream.ListenPacket
		srv.PacketForwardAddress = bindRelay((&net.ListenConfig{}).ListenPacket)
		srv.BytesPool = pool.Bytes
		if username := opts[KeyUsername]; username != "" {
			srv.Authentication = socks5.UserAuth(username, opts[KeyPassword])
		}
		return srv.Serve(ln)
	}}, nil
}

// listeners owns the BIND listeners the library keeps open after its server stops.
type listeners struct {
	listen func(ctx context.Context, network, address string) (net.Listener, error)
	mu     sync.Mutex
	closed bool
	lns    []net.Listener
}

func (l *listeners) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	ln, err := l.listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		ln.Close()
		return nil, net.ErrClosed
	}
	l.lns = append(l.lns, ln)
	return ln, nil
}

func (l *listeners) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for _, ln := range l.lns {
		ln.Close()
	}
	l.lns = nil
}

// listenRelay hands the library a relay that bindRelay binds once the control conn is known; the
// address the library passes is the client's DST.ADDR, which is not a bind request.
func listenRelay(context.Context, string, string) (net.PacketConn, error) {
	return &relaySocket{}, nil
}

// relaySocket is the client-facing relay, nil until bindRelay binds it.
type relaySocket struct{ net.PacketConn }

func (r *relaySocket) Close() error {
	if r.PacketConn == nil {
		return nil
	}
	return r.PacketConn.Close()
}

// bindRelay binds the relay through listen on a free port in the control conn's family and advertises it.
func bindRelay(listen netutils.ListenPacket) func(ctx context.Context, destination string, pc net.PacketConn, control net.Conn) (net.IP, int, error) {
	return func(ctx context.Context, destination string, pc net.PacketConn, control net.Conn) (net.IP, int, error) {
		r := pc.(*relaySocket)
		var err error
		if r.PacketConn, err = listen(ctx, udpFamily(control.LocalAddr(), "udp"), ":0"); err != nil {
			return nil, 0, err
		}
		return relayAddress(ctx, destination, r, control)
	}
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
