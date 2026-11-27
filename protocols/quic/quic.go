// Package quic is the quic layer, a Stream over datagrams on golang.org/x/net/quic, itself a work in progress not ready for production.
package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/quic"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

// alpn is the application protocol both ends negotiate, which a peer outside permuteproxy must offer.
const alpn = "permuteproxy"

// maxIdle is x/net/quic's idle timeout when zero; tests shorten it.
var maxIdle time.Duration

// keepAlive pings an idle connection before x/net/quic's 30 s idle timeout, or at half a shorter one.
const keepAlive = 10 * time.Second

func NewAdapter(opts permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	values := protoutils.Values(opts)
	// Each side builds only its own config: dialers read the CA file, listeners the key material.
	clientConfig := sync.OnceValues(func() (*quic.Config, error) {
		config, err := tlsutils.NewClient(values)
		if err != nil {
			return nil, err
		}
		return quicConfig(config), nil
	})
	var serverConfig atomic.Pointer[quic.Config] // what the latest BeforeListen built
	shared := &pool{}
	return &permuteproxy.AdapterFuncs{
		BeforeDial: func() error {
			_, err := clientConfig()
			return err
		},
		BeforeListen: func() error {
			config, err := tlsutils.NewServer(values)
			if err != nil {
				return err
			}
			serverConfig.Store(quicConfig(config))
			return nil
		},
		Stream: &permuteproxy.Link{
			Over: permuteproxy.Packet,
			Open: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
				config, _ := clientConfig() // BeforeDial has returned its error
				return dial(ctx, carrier, config, shared)
			},
			PacketListener: func(pc net.PacketConn) (net.Listener, error) {
				return listen(pc, serverConfig.Load())
			},
		},
		Close: shared.close,
	}, nil
}

func quicConfig(config *tls.Config) *quic.Config {
	config.MinVersion = tls.VersionTLS13
	config.NextProtos = []string{alpn}
	return &quic.Config{TLSConfig: config, MaxIdleTimeout: maxIdle, KeepAlivePeriod: keepAlive}
}

// dial opens a stream to the endpoint, on the connection the adapter holds when it has one,
// else on a connection of its own over a carrier it obtains.
func dial(ctx context.Context, obtain func(context.Context) (net.Conn, error), config *quic.Config, shared *pool) (net.Conn, error) {
	if l := shared.acquire(); l != nil {
		wait, cancel := context.WithTimeout(ctx, openWait)
		stream, err := l.open(wait)
		cancel()
		if err == nil {
			return newConn(stream, l.local, l.remote, l.done), nil
		}
		// A connection that ended or is full refuses the stream, and this dial opens the next one.
		l.retire()
		l.done()
		if ctx.Err() != nil {
			return nil, err
		}
	}
	carrier, err := obtain(ctx)
	if err != nil {
		return nil, err
	}
	peer, ok := addrPort(carrier.RemoteAddr())
	local, localOK := addrPort(carrier.LocalAddr())
	if !ok || !localOK {
		carrier.Close()
		return nil, fmt.Errorf("quic from %v to %v: not ip:port: %w", carrier.LocalAddr(), carrier.RemoteAddr(), permuteproxy.ErrUnsupported)
	}
	if peer.Addr().IsUnspecified() {
		// As net.Dial does, take an unspecified peer for this host, at the loopback of the socket's family.
		loopback := netip.IPv6Loopback()
		if local.Addr().Is4() {
			loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
		peer = netip.AddrPortFrom(loopback, peer.Port())
	}
	sock := &socket{PacketConn: carrier.(net.PacketConn)}
	endpoint, err := quic.NewEndpoint(sock, nil)
	if err != nil {
		sock.Close()
		return nil, err
	}
	qc, err := endpoint.Dial(ctx, "udp", peer.String(), config)
	if err != nil {
		closeEndpoint(endpoint)
		return nil, err
	}
	l := shared.add(endpoint, qc, carrier.LocalAddr(), carrier.RemoteAddr())
	stream, err := l.open(ctx)
	if err != nil {
		l.retire()
		l.done()
		return nil, err
	}
	return newConn(stream, l.local, l.remote, l.done), nil
}

// closeEndpoint aborts the connections of e without waiting on their peers, and returns once e has closed its socket.
func closeEndpoint(e *quic.Endpoint) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.Close(ctx)
	e.Close(context.Background())
}

// addrPort is addr as the ip:port an Endpoint needs, unmapped as an Endpoint keeps its peers.
func addrPort(addr net.Addr) (netip.AddrPort, bool) {
	var ap netip.AddrPort
	if a, ok := addr.(*net.UDPAddr); ok {
		ap = a.AddrPort()
		if len(a.IP) == 0 {
			// An empty host, as in ":port", is unspecified.
			ap = netip.AddrPortFrom(netip.IPv6Unspecified(), ap.Port())
		}
	} else {
		ap, _ = netip.ParseAddrPort(addr.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ap.IsValid()
}

// socket is a carrier as an Endpoint reads it, its peers unmapped as the Endpoint's own are.
type socket struct {
	net.PacketConn
}

func (s *socket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(b)
	if a, ok := addr.(*net.UDPAddr); ok {
		// A dual-stack socket reports IPv4 peers v4-mapped, which the Endpoint takes for another peer.
		ap, _ := addrPort(a)
		addr = net.UDPAddrFromAddrPort(ap)
	}
	return n, addr, err
}

// listener hands out the streams of every connection its Endpoint accepts.
type listener struct {
	endpoint *quic.Endpoint
	addr     net.Addr
	ctx      context.Context
	cancel   context.CancelFunc
	conns    chan net.Conn
	failed   chan struct{} // closed once the Endpoint accepts no more connections
	err      error         // why, set before failed closes
	wg       sync.WaitGroup
	once     sync.Once
}

func listen(pc net.PacketConn, config *quic.Config) (net.Listener, error) {
	if _, ok := addrPort(pc.LocalAddr()); !ok {
		pc.Close()
		return nil, fmt.Errorf("quic at %v: not ip:port: %w", pc.LocalAddr(), permuteproxy.ErrUnsupported)
	}
	sock := &socket{PacketConn: pc}
	endpoint, err := quic.NewEndpoint(sock, config)
	if err != nil {
		sock.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{endpoint: endpoint, addr: pc.LocalAddr(), ctx: ctx, cancel: cancel, conns: make(chan net.Conn), failed: make(chan struct{})}
	l.wg.Add(1)
	go l.acceptConns()
	return l, nil
}

func (l *listener) acceptConns() {
	defer l.wg.Done()
	for {
		qc, err := l.endpoint.Accept(l.ctx)
		if err != nil {
			l.err = err
			close(l.failed)
			return
		}
		l.wg.Add(1)
		go l.acceptStreams(qc)
	}
}

func (l *listener) acceptStreams(qc *quic.Conn) {
	defer l.wg.Done()
	// A connection its peer closed drains only once this side closes it too.
	defer qc.Abort(nil)
	remote := net.UDPAddrFromAddrPort(qc.RemoteAddr())
	for {
		stream, err := qc.AcceptStream(l.ctx)
		if err != nil {
			return
		}
		select {
		case l.conns <- newConn(stream, l.Addr(), remote, nil):
		case <-l.ctx.Done():
			return
		}
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.failed:
		if l.ctx.Err() != nil {
			return nil, &net.OpError{Op: "accept", Net: "quic", Addr: l.Addr(), Err: net.ErrClosed}
		}
		return nil, &net.OpError{Op: "accept", Net: "quic", Addr: l.Addr(), Err: l.err}
	}
}

func (l *listener) Close() error {
	l.once.Do(func() {
		l.cancel()
		closeEndpoint(l.endpoint)
		l.wg.Wait()
	})
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.addr
}
