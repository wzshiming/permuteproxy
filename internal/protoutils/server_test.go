package protoutils

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func listenLoopback(ctx context.Context) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
}

// acceptLoop mimics a library Serve: it blocks in Accept until the listener closes.
func acceptLoop(_ context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		conn.Close()
	}
}

func run(s *Server, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	return done
}

func wait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func assertClosed(t *testing.T, addr net.Addr) {
	t.Helper()
	if conn, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener still open")
	}
}

func TestServerCloseStopsRun(t *testing.T) {
	bound := make(chan net.Addr, 1)
	var served atomic.Int32
	s := NewServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, func(ctx context.Context, ln net.Listener) error {
		served.Add(1)
		return acceptLoop(ctx, ln)
	})
	done := run(s, context.Background())
	addr := <-bound
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, done); err != nil {
		t.Fatalf("Run = %v after Close, want nil", err)
	}
	assertClosed(t, addr)
	if err := s.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if served.Load() != 1 {
		t.Fatalf("serve called %d times", served.Load())
	}
}

func TestServerCancelStopsRun(t *testing.T) {
	bound := make(chan net.Addr, 1)
	serveCtx := make(chan context.Context, 1)
	s := NewServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, func(ctx context.Context, ln net.Listener) error {
		serveCtx <- ctx
		return acceptLoop(ctx, ln)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := run(s, ctx)
	addr := <-bound
	inner := <-serveCtx
	cancel()
	if err := wait(t, done); err != nil {
		t.Fatalf("Run = %v after cancel, want nil", err)
	}
	assertClosed(t, addr)
	if inner.Err() == nil {
		t.Fatal("serve context survived cancellation")
	}
}

func TestServerCloseCancelsServeContext(t *testing.T) {
	serveCtx := make(chan context.Context, 1)
	s := NewServer(listenLoopback, func(ctx context.Context, ln net.Listener) error {
		serveCtx <- ctx
		return acceptLoop(ctx, ln)
	})
	done := run(s, context.Background())
	inner := <-serveCtx
	s.Close()
	wait(t, done)
	if inner.Err() == nil {
		t.Fatal("Close left the serve context alive")
	}
}

func TestServerCloseBeforeRun(t *testing.T) {
	var listens atomic.Int32
	s := NewServer(func(ctx context.Context) (net.Listener, error) {
		listens.Add(1)
		return listenLoopback(ctx)
	}, acceptLoop)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, run(s, context.Background())); err != nil {
		t.Fatalf("Run after Close = %v, want nil", err)
	}
	if listens.Load() != 0 {
		t.Fatal("Run bound a listener after Close")
	}
}

func TestServerReportsErrors(t *testing.T) {
	bindErr := errors.New("bind failed")
	s := NewServer(func(context.Context) (net.Listener, error) { return nil, bindErr }, acceptLoop)
	if err := wait(t, run(s, context.Background())); !errors.Is(err, bindErr) {
		t.Fatalf("Run = %v, want bind error", err)
	}

	serveErr := errors.New("serve failed")
	bound := make(chan net.Addr, 1)
	s = NewServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, func(context.Context, net.Listener) error { return serveErr })
	if err := wait(t, run(s, context.Background())); !errors.Is(err, serveErr) {
		t.Fatalf("Run = %v, want serve error", err)
	}
	assertClosed(t, <-bound)
	if err := s.Close(); err != nil {
		t.Fatalf("Close after failed serve = %v", err)
	}
}
