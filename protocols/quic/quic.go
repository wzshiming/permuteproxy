// Package quic is the quic layer, a Stream over datagrams on golang.org/x/net/quic, itself a work in progress not ready for production.
package quic

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/net/quic"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

// alpn is the application protocol both ends negotiate, which a peer outside permuteproxy must offer.
const alpn = "permuteproxy"

func NewAdapter(opts permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	values := protoutils.Values(opts)
	// Each side's config is built where it is needed: the CA file only by dialers, key material
	// only by listeners.
	clientConfig := sync.OnceValues(func() (*quic.Config, error) {
		config, err := tlsutils.NewClient(values)
		if err != nil {
			return nil, err
		}
		return quicConfig(config), nil
	})
	var serverConfig atomic.Pointer[quic.Config] // what the latest BeforeListen built
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
			Client: func(ctx context.Context, carrier net.Conn) (net.Conn, error) {
				config, _ := clientConfig() // BeforeDial has returned its error
				return dial(ctx, carrier, config)
			},
			PacketListener: func(pc net.PacketConn) (net.Listener, error) {
				return listen(pc, serverConfig.Load())
			},
		},
	}, nil
}

func quicConfig(config *tls.Config) *quic.Config {
	config.NextProtos = []string{alpn}
	return &quic.Config{TLSConfig: config}
}

// dial opens one QUIC connection over the carrier to its default peer, and one stream on it.
func dial(ctx context.Context, carrier net.Conn, config *quic.Config) (net.Conn, error) {
	sock := &socket{PacketConn: carrier.(net.PacketConn)}
	endpoint, err := quic.NewEndpoint(sock, nil)
	if err != nil {
		sock.Close()
		return nil, err
	}
	release := func() {
		closeEndpoint(endpoint)
		sock.Close()
	}
	qc, err := endpoint.Dial(ctx, "udp", carrier.RemoteAddr().String(), config)
	if err != nil {
		release()
		return nil, err
	}
	stream, err := qc.NewStream(ctx)
	if err != nil {
		release()
		return nil, err
	}
	// A stream reaches the peer with its first frame, so an empty one opens it for a listener that speaks first.
	stream.Flush()
	return newConn(stream, carrier.LocalAddr(), carrier.RemoteAddr(), release), nil
}

// closeEndpoint aborts the connections of e without waiting on their peers, and returns once e has stopped reading.
func closeEndpoint(e *quic.Endpoint) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.Close(ctx)
	e.Close(context.Background())
}

// socket is a carrier as an Endpoint reads it: closed once, its peers unmapped as the Endpoint's own are.
type socket struct {
	net.PacketConn
	once sync.Once
	err  error
}

func (s *socket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(b)
	if a, ok := addr.(*net.UDPAddr); ok {
		// A dual-stack socket reports IPv4 peers v4-mapped, which the Endpoint takes for another peer.
		ap := a.AddrPort()
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	return n, addr, err
}

func (s *socket) Close() error {
	s.once.Do(func() { s.err = s.PacketConn.Close() })
	return s.err
}

// listener hands out the streams of every connection its Endpoint accepts.
type listener struct {
	endpoint *quic.Endpoint
	sock     *socket
	ctx      context.Context
	cancel   context.CancelFunc
	conns    chan net.Conn
	failed   chan struct{} // closed once the Endpoint accepts no more connections
	err      error         // why, set before failed closes
	wg       sync.WaitGroup
	once     sync.Once
}

func listen(pc net.PacketConn, config *quic.Config) (net.Listener, error) {
	sock := &socket{PacketConn: pc}
	endpoint, err := quic.NewEndpoint(sock, config)
	if err != nil {
		sock.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{endpoint: endpoint, sock: sock, ctx: ctx, cancel: cancel, conns: make(chan net.Conn), failed: make(chan struct{})}
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
		l.sock.Close()
		l.wg.Wait()
	})
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.sock.LocalAddr()
}
