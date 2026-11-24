// Package serverutils binds, serves and stops the carriers of a proxy server.
package serverutils

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

var errRunning = errors.New("server already running")

// Server binds its resource on Run and serves it until Close or context cancellation, either of which makes Run return nil.
type Server struct {
	bind  func(ctx context.Context) (io.Closer, error)
	serve func(ctx context.Context, res io.Closer) error

	mu      sync.Mutex
	closed  bool
	running bool
	cancel  context.CancelFunc
	res     io.Closer
}

func newServer[R io.Closer](bind func(ctx context.Context) (R, error), serve func(ctx context.Context, res R) error) *Server {
	return &Server{
		bind: func(ctx context.Context) (io.Closer, error) {
			res, err := bind(ctx)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
		serve: func(ctx context.Context, res io.Closer) error { return serve(ctx, res.(R)) },
	}
}

// NewServer binds each of listen and listenPacket that is set, all or none, then serves them until the first serve returns.
func NewServer(listen func(ctx context.Context) (net.Listener, error), listenPacket func(ctx context.Context) (net.PacketConn, error), serveStream func(ctx context.Context, ln net.Listener) error, servePacket func(ctx context.Context, pc net.PacketConn) error) *Server {
	return newServer(func(ctx context.Context) (*resources, error) {
		res := &resources{}
		if listen != nil {
			ln, err := listen(ctx)
			if err != nil {
				return nil, err
			}
			res.ln = newListener(ln)
		}
		if listenPacket != nil {
			pc, err := listenPacket(ctx)
			if err != nil {
				res.Close()
				return nil, err
			}
			res.pc = pc
		}
		return res, nil
	}, func(ctx context.Context, res *resources) error {
		// The other serve may wait on the context alone, so it is canceled before the resources close.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errs := make(chan error, 2)
		n := 0
		if res.ln != nil {
			n++
			go func() { errs <- serveStream(ctx, res.ln) }()
		}
		if res.pc != nil {
			n++
			go func() { errs <- servePacket(ctx, res.pc) }()
		}
		err := <-errs
		cancel()
		res.Close()
		for i := 1; i < n; i++ {
			<-errs
		}
		return err
	})
}

// resources is what a plane server binds; Close is idempotent since serve, Run and Close all reach it.
type resources struct {
	ln   *listener
	pc   net.PacketConn
	once sync.Once
	err  error
}

func (r *resources) Close() error {
	r.once.Do(func() {
		if r.ln != nil {
			r.err = r.ln.Close()
		}
		if r.pc != nil {
			if err := r.pc.Close(); r.err == nil {
				r.err = err
			}
		}
	})
	return r.err
}

// Run binds and serves, one Run at a time; after Close it returns nil without binding.
func (s *Server) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if ok, err := s.begin(cancel); !ok {
		return err
	}
	defer s.end()
	if ctx.Err() != nil {
		return nil
	}
	res, err := s.bind(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer res.Close()
	if ctx.Err() != nil || !s.hold(res) {
		return nil
	}
	defer context.AfterFunc(ctx, func() { res.Close() })()
	err = s.serve(ctx, res)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Close stops the current Run, closing what it bound, and turns every later Run into a no-op.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	res := s.res
	s.res = nil
	s.mu.Unlock()
	if res == nil {
		return nil
	}
	return res.Close()
}

// begin claims the server for one Run; after Close it reports false without an error.
func (s *Server) begin(cancel context.CancelFunc) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, nil
	}
	if s.running {
		return false, errRunning
	}
	s.running, s.cancel = true, cancel
	return true, nil
}

func (s *Server) hold(res io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.res = res
	return true
}

func (s *Server) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.cancel, s.res = false, nil, nil
}

// listener closes accepted connections along with itself; the wrapped servers honor the context only after the handshake.
type listener struct {
	net.Listener
	mu     sync.Mutex
	closed bool
	conns  map[*conn]struct{}
}

func newListener(ln net.Listener) *listener {
	return &listener{Listener: ln, conns: map[*conn]struct{}{}}
}

func (l *listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &conn{Conn: raw, ln: l}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	return c, nil
}

func (l *listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	err := l.Listener.Close()
	for c := range conns {
		c.Close()
	}
	return err
}

func (l *listener) forget(c *conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, c)
}

type conn struct {
	net.Conn
	ln   *listener
	once sync.Once
	err  error
}

func (c *conn) Close() error {
	c.once.Do(func() {
		c.ln.forget(c)
		c.err = c.Conn.Close()
	})
	return c.err
}
