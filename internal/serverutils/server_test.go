package serverutils

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	started := make(chan struct{})
	var served atomic.Int32
	s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, nil, func(ctx context.Context, ln net.Listener) error {
		served.Add(1)
		close(started)
		return acceptLoop(ctx, ln)
	}, nil)
	done := run(s, context.Background())
	addr := <-bound
	<-started
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
	s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, nil, func(ctx context.Context, ln net.Listener) error {
		serveCtx <- ctx
		return acceptLoop(ctx, ln)
	}, nil)
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
	s := NewPlaneServer(listenLoopback, nil, func(ctx context.Context, ln net.Listener) error {
		serveCtx <- ctx
		return acceptLoop(ctx, ln)
	}, nil)
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
	s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		listens.Add(1)
		return listenLoopback(ctx)
	}, nil, acceptLoop, nil)
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
	s := NewPlaneServer(func(context.Context) (net.Listener, error) { return nil, bindErr }, nil, acceptLoop, nil)
	if err := wait(t, run(s, context.Background())); !errors.Is(err, bindErr) {
		t.Fatalf("Run = %v, want bind error", err)
	}

	serveErr := errors.New("serve failed")
	bound := make(chan net.Addr, 1)
	s = NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, nil, func(context.Context, net.Listener) error { return serveErr }, nil)
	if err := wait(t, run(s, context.Background())); !errors.Is(err, serveErr) {
		t.Fatalf("Run = %v, want serve error", err)
	}
	assertClosed(t, <-bound)
	if err := s.Close(); err != nil {
		t.Fatalf("Close after failed serve = %v", err)
	}
}

// handshakeLoop mimics a library Serve whose handlers block reading a two byte greeting.
func handshakeLoop(accepted chan<- struct{}, reads chan<- error) func(context.Context, net.Listener) error {
	return func(_ context.Context, ln net.Listener) error {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			accepted <- struct{}{}
			go func() {
				_, err := io.ReadFull(conn, make([]byte, 2))
				reads <- err
			}()
		}
	}
}

func readErr(t *testing.T, conn net.Conn) error {
	t.Helper()
	got := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		got <- err
	}()
	select {
	case err := <-got:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("connection survived the server stop")
		return nil
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen", what)
		var zero T
		return zero
	}
}

func TestServerStopReleasesAcceptedConns(t *testing.T) {
	for _, tt := range []struct {
		name    string
		partial string
		cancel  bool
	}{
		{"close idle", "", false},
		{"close partial", "\x05", false},
		{"cancel idle", "", true},
		{"cancel partial", "\x05", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bound := make(chan net.Addr, 1)
			accepted := make(chan struct{}, 1)
			reads := make(chan error, 1)
			s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
				ln, err := listenLoopback(ctx)
				if err == nil {
					bound <- ln.Addr()
				}
				return ln, err
			}, nil, handshakeLoop(accepted, reads), nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := run(s, ctx)
			client, err := net.Dial("tcp", recv(t, bound, "bind").String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			recv(t, accepted, "accept")
			if tt.partial != "" {
				if _, err := client.Write([]byte(tt.partial)); err != nil {
					t.Fatal(err)
				}
			}
			if tt.cancel {
				cancel()
			} else if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := wait(t, done); err != nil {
				t.Fatalf("Run = %v, want nil", err)
			}
			if err := recv(t, reads, "server read"); err == nil {
				t.Fatal("server side read completed without error")
			}
			if err := readErr(t, client); err == nil {
				t.Fatal("client read succeeded after the server stopped")
			}
		})
	}
}

func TestServerServeExitClosesConns(t *testing.T) {
	serveErr := errors.New("serve failed")
	bound := make(chan net.Addr, 1)
	accepted := make(chan struct{}, 1)
	reads := make(chan error, 1)
	release := make(chan struct{})
	s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, nil, func(_ context.Context, ln net.Listener) error {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		accepted <- struct{}{}
		go func() {
			_, err := io.ReadFull(conn, make([]byte, 2))
			reads <- err
		}()
		<-release
		return serveErr
	}, nil)
	done := run(s, context.Background())
	client, err := net.Dial("tcp", recv(t, bound, "bind").String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	recv(t, accepted, "accept")
	close(release)
	if err := wait(t, done); !errors.Is(err, serveErr) {
		t.Fatalf("Run = %v, want serve error", err)
	}
	if err := recv(t, reads, "server read"); err == nil {
		t.Fatal("server side read completed without error")
	}
	if err := readErr(t, client); err == nil {
		t.Fatal("client read succeeded after serve returned")
	}
}

// fakeListener hands out connections on demand so tests can order Accept against Close.
type fakeListener struct {
	conns  chan net.Conn
	closes atomic.Int32
}

func (l *fakeListener) Accept() (net.Conn, error) {
	return <-l.conns, nil
}

func (l *fakeListener) Close() error {
	l.closes.Add(1)
	return nil
}

func (l *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero}
}

type countingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func pipeConn() *countingConn {
	c1, c2 := net.Pipe()
	c2.Close()
	return &countingConn{Conn: c1}
}

func TestServerAcceptAfterCloseClosesConn(t *testing.T) {
	fake := &fakeListener{conns: make(chan net.Conn)}
	entered := make(chan struct{}, 1)
	accepted := make(chan error, 1)
	s := NewPlaneServer(func(context.Context) (net.Listener, error) { return fake, nil }, nil,
		func(_ context.Context, ln net.Listener) error {
			entered <- struct{}{}
			_, err := ln.Accept()
			accepted <- err
			return err
		}, nil)
	done := run(s, context.Background())
	recv(t, entered, "serve")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	conn := pipeConn()
	fake.conns <- conn
	if err := recv(t, accepted, "accept"); err == nil {
		t.Fatal("Accept handed out a connection after Close")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("late connection closed %d times, want 1", got)
	}
	if err := wait(t, done); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if got := fake.closes.Load(); got != 1 {
		t.Fatalf("listener closed %d times, want 1", got)
	}
}

func TestServerCloseIsIdempotent(t *testing.T) {
	fake := &fakeListener{conns: make(chan net.Conn, 2)}
	first, second := pipeConn(), pipeConn()
	fake.conns <- first
	fake.conns <- second
	result := make(chan error, 1)
	s := NewPlaneServer(func(context.Context) (net.Listener, error) { return fake, nil }, nil,
		func(_ context.Context, ln net.Listener) error {
			c1, err := ln.Accept()
			if err != nil {
				return err
			}
			c2, err := ln.Accept()
			if err != nil {
				return err
			}
			for i, fn := range []func() error{c1.Close, c1.Close, ln.Close, ln.Close, c2.Close} {
				if err := fn(); err != nil {
					return fmt.Errorf("close %d = %w", i, err)
				}
			}
			result <- nil
			return nil
		}, nil)
	if err := wait(t, run(s, context.Background())); err != nil {
		t.Fatalf("Run = %v", err)
	}
	recv(t, result, "serve")
	if first.closes.Load() != 1 || second.closes.Load() != 1 || fake.closes.Load() != 1 {
		t.Fatalf("closes: first %d second %d listener %d, want 1 each", first.closes.Load(), second.closes.Load(), fake.closes.Load())
	}
}

func TestServerCanceledContextDoesNotBind(t *testing.T) {
	var listens atomic.Int32
	s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		listens.Add(1)
		return listenLoopback(ctx)
	}, nil, acceptLoop, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := wait(t, run(s, ctx)); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if listens.Load() != 0 {
		t.Fatal("Run bound a listener under a canceled context")
	}
}

func TestServerBindFailingOnStopReturnsNil(t *testing.T) {
	for _, cancelCtx := range []bool{true, false} {
		name := "close"
		if cancelCtx {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
				entered <- struct{}{}
				<-ctx.Done()
				return nil, fmt.Errorf("bind: %w", ctx.Err())
			}, nil, acceptLoop, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := run(s, ctx)
			recv(t, entered, "listen")
			if cancelCtx {
				cancel()
			} else if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := wait(t, done); err != nil {
				t.Fatalf("Run = %v, want nil for a bind that failed because of the stop", err)
			}
		})
	}
}

func TestServerStopDuringBind(t *testing.T) {
	for _, cancelCtx := range []bool{true, false} {
		name := "close"
		if cancelCtx {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{}, 1)
			fake := &fakeListener{conns: make(chan net.Conn)}
			var served atomic.Int32
			s := NewPlaneServer(func(context.Context) (net.Listener, error) {
				entered <- struct{}{}
				<-release
				return fake, nil
			}, nil, func(context.Context, net.Listener) error {
				served.Add(1)
				return nil
			}, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := run(s, ctx)
			recv(t, entered, "listen")
			if cancelCtx {
				cancel()
			} else if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			close(release)
			if err := wait(t, done); err != nil {
				t.Fatalf("Run = %v, want nil", err)
			}
			if served.Load() != 0 {
				t.Fatal("serve started after the stop")
			}
			if got := fake.closes.Load(); got != 1 {
				t.Fatalf("late listener closed %d times, want 1", got)
			}
		})
	}
}

func TestServerRunIsExclusive(t *testing.T) {
	bound := make(chan net.Addr, 2)
	var listens atomic.Int32
	s := NewPlaneServer(func(ctx context.Context) (net.Listener, error) {
		listens.Add(1)
		ln, err := listenLoopback(ctx)
		if err == nil {
			bound <- ln.Addr()
		}
		return ln, err
	}, nil, acceptLoop, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := run(s, ctx)
	recv(t, bound, "bind")
	if err := wait(t, run(s, context.Background())); err == nil {
		t.Fatal("second Run while running = nil, want an error")
	}
	select {
	case err := <-first:
		t.Fatalf("first Run returned %v because of the second", err)
	default:
	}
	cancel()
	if err := wait(t, first); err != nil {
		t.Fatalf("first Run = %v, want nil", err)
	}
	again := run(s, context.Background())
	addr := recv(t, bound, "rebind")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, again); err != nil {
		t.Fatalf("Run after cancel = %v, want nil", err)
	}
	assertClosed(t, addr)
	if listens.Load() != 2 {
		t.Fatalf("listen called %d times, want 2", listens.Load())
	}
}

func listenPacketLoopback(ctx context.Context) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
}

// readLoop mimics a library ServePacket: it blocks in ReadFrom until the conn closes.
func readLoop(_ context.Context, pc net.PacketConn) error {
	buf := make([]byte, 64)
	for {
		if _, _, err := pc.ReadFrom(buf); err != nil {
			return err
		}
	}
}

type countingPacketConn struct {
	net.PacketConn
	closes atomic.Int32
}

func (c *countingPacketConn) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

func TestPlaneServerBindsBothBeforeServing(t *testing.T) {
	var binds atomic.Int32
	seen := make(chan int32, 2)
	var pc *countingPacketConn
	bound := make(chan net.Addr, 1)
	s := NewPlaneServer(
		func(ctx context.Context) (net.Listener, error) {
			binds.Add(1)
			ln, err := listenLoopback(ctx)
			if err == nil {
				bound <- ln.Addr()
			}
			return ln, err
		},
		func(ctx context.Context) (net.PacketConn, error) {
			binds.Add(1)
			raw, err := listenPacketLoopback(ctx)
			if err != nil {
				return nil, err
			}
			pc = &countingPacketConn{PacketConn: raw}
			return pc, nil
		},
		func(ctx context.Context, ln net.Listener) error { seen <- binds.Load(); return acceptLoop(ctx, ln) },
		func(ctx context.Context, pc net.PacketConn) error { seen <- binds.Load(); return readLoop(ctx, pc) })
	done := run(s, context.Background())
	for i := 0; i < 2; i++ {
		if got := recv(t, seen, "serve"); got != 2 {
			t.Fatalf("serve started after %d binds, want 2", got)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, done); err != nil {
		t.Fatalf("Run = %v after Close, want nil", err)
	}
	assertClosed(t, recv(t, bound, "bind"))
	if got := pc.closes.Load(); got != 1 {
		t.Fatalf("packet conn closed %d times, want 1", got)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestPlaneServerBindFailureReleasesFirst(t *testing.T) {
	bindErr := errors.New("packet bind failed")
	fake := &fakeListener{conns: make(chan net.Conn)}
	var served atomic.Int32
	s := NewPlaneServer(
		func(context.Context) (net.Listener, error) { return fake, nil },
		func(context.Context) (net.PacketConn, error) { return nil, bindErr },
		func(context.Context, net.Listener) error { served.Add(1); return nil },
		func(context.Context, net.PacketConn) error { served.Add(1); return nil })
	if err := wait(t, run(s, context.Background())); !errors.Is(err, bindErr) {
		t.Fatalf("Run = %v, want the packet bind error", err)
	}
	if got := fake.closes.Load(); got != 1 {
		t.Fatalf("listener closed %d times after the packet bind failed, want 1", got)
	}
	if served.Load() != 0 {
		t.Fatal("serve started after a failed bind")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close after failed bind = %v", err)
	}
}

func TestPlaneServerServeErrorStopsBoth(t *testing.T) {
	serveErr := errors.New("packet serve failed")
	var pc *countingPacketConn
	bound := make(chan net.Addr, 1)
	streamDone := make(chan error, 1)
	s := NewPlaneServer(
		func(ctx context.Context) (net.Listener, error) {
			ln, err := listenLoopback(ctx)
			if err == nil {
				bound <- ln.Addr()
			}
			return ln, err
		},
		func(ctx context.Context) (net.PacketConn, error) {
			raw, err := listenPacketLoopback(ctx)
			if err != nil {
				return nil, err
			}
			pc = &countingPacketConn{PacketConn: raw}
			return pc, nil
		},
		func(ctx context.Context, ln net.Listener) error {
			err := acceptLoop(ctx, ln)
			streamDone <- err
			return err
		},
		func(context.Context, net.PacketConn) error { return serveErr })
	if err := wait(t, run(s, context.Background())); !errors.Is(err, serveErr) {
		t.Fatalf("Run = %v, want the packet serve error", err)
	}
	if err := recv(t, streamDone, "stream serve exit"); err == nil {
		t.Fatal("stream serve returned nil, want the closed listener error")
	}
	assertClosed(t, recv(t, bound, "bind"))
	if got := pc.closes.Load(); got != 1 {
		t.Fatalf("packet conn closed %d times, want 1", got)
	}
}

// waitCtx mimics a serve whose handlers wait on the context alone, never touching the resource.
func waitCtx(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func returns(err error) func(context.Context) error {
	return func(context.Context) error { return err }
}

func TestPlaneServerFirstReturnCancelsOther(t *testing.T) {
	serveErr := errors.New("serve failed")
	for _, tt := range []struct {
		name           string
		stream, packet func(context.Context) error
		want           error
	}{
		{"stream error first", returns(serveErr), waitCtx, serveErr},
		{"packet error first", waitCtx, returns(serveErr), serveErr},
		{"stream success first", returns(nil), waitCtx, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var pc *countingPacketConn
			bound := make(chan net.Addr, 1)
			exits := make(chan error, 2)
			report := func(serve func(context.Context) error) func(context.Context) error {
				return func(ctx context.Context) error {
					err := serve(ctx)
					exits <- err
					return err
				}
			}
			stream, packet := report(tt.stream), report(tt.packet)
			s := NewPlaneServer(
				func(ctx context.Context) (net.Listener, error) {
					ln, err := listenLoopback(ctx)
					if err == nil {
						bound <- ln.Addr()
					}
					return ln, err
				},
				func(ctx context.Context) (net.PacketConn, error) {
					raw, err := listenPacketLoopback(ctx)
					if err != nil {
						return nil, err
					}
					pc = &countingPacketConn{PacketConn: raw}
					return pc, nil
				},
				func(ctx context.Context, _ net.Listener) error { return stream(ctx) },
				func(ctx context.Context, _ net.PacketConn) error { return packet(ctx) })
			if err := wait(t, run(s, context.Background())); !errors.Is(err, tt.want) {
				t.Fatalf("Run = %v, want %v", err, tt.want)
			}
			first, second := recv(t, exits, "serve exit"), recv(t, exits, "serve exit")
			if !errors.Is(second, context.Canceled) {
				first, second = second, first
			}
			if !errors.Is(first, tt.want) || !errors.Is(second, context.Canceled) {
				t.Fatalf("serves returned %v and %v, want %v and context.Canceled", first, second, tt.want)
			}
			assertClosed(t, recv(t, bound, "bind"))
			if got := pc.closes.Load(); got != 1 {
				t.Fatalf("packet conn closed %d times, want 1", got)
			}
		})
	}
}

func TestPlaneServerStopReachesWaitingServes(t *testing.T) {
	for _, cancelCtx := range []bool{true, false} {
		name := "close"
		if cancelCtx {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{}, 2)
			s := NewPlaneServer(listenLoopback, listenPacketLoopback,
				func(ctx context.Context, _ net.Listener) error { started <- struct{}{}; return waitCtx(ctx) },
				func(ctx context.Context, _ net.PacketConn) error { started <- struct{}{}; return waitCtx(ctx) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := run(s, ctx)
			recv(t, started, "first serve")
			recv(t, started, "second serve")
			if cancelCtx {
				cancel()
			} else if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := wait(t, done); err != nil {
				t.Fatalf("Run = %v, want nil", err)
			}
		})
	}
}

func TestPlaneServerBindsOnlyWhatIsSet(t *testing.T) {
	for _, name := range []string{"stream", "packet"} {
		t.Run(name, func(t *testing.T) {
			var binds atomic.Int32
			listen := func(ctx context.Context) (net.Listener, error) { binds.Add(1); return listenLoopback(ctx) }
			listenPacket := func(ctx context.Context) (net.PacketConn, error) { binds.Add(1); return listenPacketLoopback(ctx) }
			if name == "stream" {
				listenPacket = nil
			} else {
				listen = nil
			}
			started := make(chan string, 2)
			s := NewPlaneServer(listen, listenPacket,
				func(ctx context.Context, ln net.Listener) error { started <- "stream"; return acceptLoop(ctx, ln) },
				func(ctx context.Context, pc net.PacketConn) error { started <- "packet"; return readLoop(ctx, pc) })
			done := run(s, context.Background())
			if got := recv(t, started, "serve"); got != name {
				t.Fatalf("%s serve started, want %s", got, name)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := wait(t, done); err != nil {
				t.Fatalf("Run = %v after Close, want nil", err)
			}
			if got := binds.Load(); got != 1 {
				t.Fatalf("bound %d times, want once", got)
			}
			select {
			case got := <-started:
				t.Fatalf("%s serve started too", got)
			default:
			}
		})
	}
}
