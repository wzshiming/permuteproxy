package protoutils

import (
	"context"
	"errors"
	"net"
	"sync"
)

var errRunning = errors.New("server already running")

// Server binds a listener on Run and serves it until Close or context cancellation, either of
// which makes Run return nil; the bind and serve steps are supplied by the protocol.
type Server struct {
	listen func(ctx context.Context) (net.Listener, error)
	serve  func(ctx context.Context, ln net.Listener) error

	mu      sync.Mutex
	closed  bool
	running bool
	cancel  context.CancelFunc
	ln      *listener
}

func NewServer(listen func(ctx context.Context) (net.Listener, error), serve func(ctx context.Context, ln net.Listener) error) *Server {
	return &Server{listen: listen, serve: serve}
}

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
	raw, err := s.listen(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	ln := newListener(raw)
	defer ln.Close()
	if ctx.Err() != nil || !s.bind(ln) {
		return nil
	}
	defer context.AfterFunc(ctx, func() { ln.Close() })()
	err = s.serve(ctx, ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
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

func (s *Server) bind(ln *listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.ln = ln
	return true
}

func (s *Server) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.cancel, s.ln = false, nil, nil
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
