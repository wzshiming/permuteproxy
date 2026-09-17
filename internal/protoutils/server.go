package protoutils

import (
	"context"
	"net"
	"sync"
)

// Server binds a listener on Run and serves it until Close or context cancellation, either of
// which makes Run return nil; the bind and serve steps are supplied by the protocol.
type Server struct {
	listen func(ctx context.Context) (net.Listener, error)
	serve  func(ctx context.Context, ln net.Listener) error

	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc
	ln     net.Listener
}

func NewServer(listen func(ctx context.Context) (net.Listener, error), serve func(ctx context.Context, ln net.Listener) error) *Server {
	return &Server{listen: listen, serve: serve}
}

func (s *Server) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if !s.begin(cancel) {
		return nil
	}
	ln, err := s.listen(ctx)
	if err != nil {
		return err
	}
	if !s.bind(ln) {
		ln.Close()
		return nil
	}
	defer s.unbind()
	defer context.AfterFunc(ctx, func() { ln.Close() })()
	err = s.serve(ctx, ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	s.ln = nil
	return err
}

func (s *Server) begin(cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancel = cancel
	return !s.closed
}

func (s *Server) bind(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.ln = ln
	return true
}

func (s *Server) unbind() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
		s.ln = nil
	}
}
