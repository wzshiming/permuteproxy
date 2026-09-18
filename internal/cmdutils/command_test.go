package cmdutils

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var testAddr = netutils.NewNetAddr("cmd", "fake")

// fakeProcess stands in for a command: the test drives peer, ends it with exit and sees Kill.
type fakeProcess struct {
	net.Conn
	peer   net.Conn
	ctx    context.Context
	done   chan struct{}
	once   sync.Once
	err    error
	killed atomic.Int32
}

func (p *fakeProcess) Done() <-chan struct{} { return p.done }

func (p *fakeProcess) Err() error { return p.err }

func (p *fakeProcess) Kill() error {
	p.killed.Add(1)
	p.exit(errors.New("signal: killed"))
	return nil
}

// exit ends the command: its output closes and it is reaped with err.
func (p *fakeProcess) exit(err error) {
	p.once.Do(func() {
		p.err = err
		p.peer.Close()
		close(p.done)
	})
}

// spawner hands out fakeProcess conns, reporting each on started.
type spawner struct {
	started chan *fakeProcess
	mu      sync.Mutex
	all     []*fakeProcess
}

func newSpawner() *spawner {
	return &spawner{started: make(chan *fakeProcess, 16)}
}

func (s *spawner) dial(ctx context.Context, name string, args ...string) (net.Conn, error) {
	local, peer := net.Pipe()
	p := &fakeProcess{Conn: local, peer: peer, ctx: ctx, done: make(chan struct{})}
	s.mu.Lock()
	s.all = append(s.all, p)
	s.mu.Unlock()
	s.started <- p
	return p, nil
}

func (s *spawner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.all)
}

type result struct {
	conn net.Conn
	err  error
}

func acceptAsync(ln net.Listener) <-chan result {
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()
	return ch
}

func listenSpawner(t *testing.T, ctx context.Context, s *spawner) net.Listener {
	t.Helper()
	ln, err := Listen(ctx, s.dial, testAddr, testAddr, []string{"fake"})
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// acceptOne drives Accept through a spawn that sends one byte.
func acceptOne(t *testing.T, ln net.Listener, s *spawner) (net.Conn, *fakeProcess) {
	t.Helper()
	res := acceptAsync(ln)
	p := recv(t, s.started, "spawn")
	go p.peer.Write([]byte{1})
	r := recv(t, res, "Accept")
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.conn, p
}

func TestDialContextCanceledBeforeStart(t *testing.T) {
	s := newSpawner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialContext(ctx, s.dial, testAddr, testAddr, []string{"fake"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext = %v, want context.Canceled", err)
	}
	if _, err := Listen(ctx, s.dial, testAddr, testAddr, []string{"fake"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Listen = %v, want context.Canceled", err)
	}
	if s.count() != 0 {
		t.Fatal("command started under a canceled context")
	}
}

type ctxKey struct{}

func TestDialConnSurvivesCallerCancel(t *testing.T) {
	s := newSpawner()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "v"))
	conn, err := DialContext(ctx, s.dial, testAddr, testAddr, []string{"fake"})
	if err != nil {
		t.Fatal(err)
	}
	p := recv(t, s.started, "spawn")
	cancel()
	if p.ctx.Err() != nil {
		t.Fatal("command context canceled along with the caller's")
	}
	if p.ctx.Value(ctxKey{}) != "v" {
		t.Fatal("command context lost the caller's values")
	}
	go p.peer.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(netutils.Process); !ok {
		t.Fatal("dialed conn hides its process")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if p.ctx.Err() == nil {
		t.Fatal("command context alive after Close")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestDialContextCancelDuringStart(t *testing.T) {
	s := newSpawner()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	dial := func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return s.dial(ctx, name, args...)
	}
	res := make(chan error, 1)
	go func() {
		_, err := DialContext(ctx, dial, testAddr, testAddr, []string{"fake"})
		res <- err
	}()
	recv(t, entered, "dial")
	cancel()
	if err := recv(t, res, "DialContext"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext = %v, want context.Canceled", err)
	}
	if p := recv(t, s.started, "spawn"); p.killed.Load() != 1 {
		t.Fatalf("command started during cancellation killed %d times, want 1", p.killed.Load())
	}
}

func TestListenerSurvivesCallerCancel(t *testing.T) {
	s := newSpawner()
	ctx, cancel := context.WithCancel(context.Background())
	ln := listenSpawner(t, ctx, s)
	defer ln.Close()
	cancel()
	conn, _ := acceptOne(t, ln, s)
	conn.Close()
}

func TestListenerCloseKillsPendingSpawn(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	res := acceptAsync(ln)
	p := recv(t, s.started, "spawn")
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if r := recv(t, res, "Accept"); !errors.Is(r.err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want net.ErrClosed", r.err)
	}
	recv(t, p.done, "reap")
	if p.killed.Load() != 1 {
		t.Fatalf("pending command killed %d times, want 1", p.killed.Load())
	}
	if s.count() != 1 {
		t.Fatalf("%d commands started, want 1", s.count())
	}
}

func TestListenerAcceptedConnOutlivesClose(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	conn, p := acceptOne(t, ln, s)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if p.killed.Load() != 0 {
		t.Fatal("accepted command killed by listener Close")
	}
	if p.ctx.Err() != nil {
		t.Fatal("accepted command context canceled by listener Close")
	}
	go p.peer.Write([]byte("more"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "\x01more" {
		t.Fatalf("read %q, %v after listener Close", buf, err)
	}
	if _, ok := conn.(netutils.Process); !ok {
		t.Fatal("accepted conn hides its process")
	}
	conn.Close()
}

func TestListenerAcceptWaitsForPreviousProcess(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	conn, first := acceptOne(t, ln, s)
	conn.Close()
	res := acceptAsync(ln)
	select {
	case <-s.started:
		t.Fatal("next command started before the previous process exited")
	case <-time.After(100 * time.Millisecond):
	}
	first.exit(nil)
	second := recv(t, s.started, "next spawn")
	go second.peer.Write([]byte{1})
	if r := recv(t, res, "second Accept"); r.err != nil {
		t.Fatal(r.err)
	} else {
		r.conn.Close()
	}
}

func TestListenerAcceptProceedsOnceProcessExits(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	conn, first := acceptOne(t, ln, s)
	defer conn.Close()
	first.exit(nil)
	second, _ := acceptOne(t, ln, s)
	second.Close()
}

func TestListenerRespawnsAfterCleanExitWithoutData(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	res := acceptAsync(ln)
	first := recv(t, s.started, "spawn")
	first.exit(nil)
	second := recv(t, s.started, "respawn")
	go second.peer.Write([]byte{1})
	r := recv(t, res, "Accept")
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.conn.Close()
	if first.killed.Load() != 0 {
		t.Fatal("cleanly exited command was killed")
	}
	if s.count() != 2 {
		t.Fatalf("%d commands started, want 2", s.count())
	}
}

func TestListenerReportsFailedSpawn(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	res := acceptAsync(ln)
	exitErr := errors.New("exit status 1")
	recv(t, s.started, "spawn").exit(exitErr)
	if r := recv(t, res, "Accept"); !errors.Is(r.err, exitErr) {
		t.Fatalf("Accept = %v, want %v", r.err, exitErr)
	}
	if s.count() != 1 {
		t.Fatalf("%d commands started, want 1: a failed command must not be retried", s.count())
	}
	conn, _ := acceptOne(t, ln, s)
	conn.Close()
}

func TestListenerFallbackReportsEOFBeforeFirstByte(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	res := acceptAsync(ln)
	recv(t, peers, "spawn").Close()
	if r := recv(t, res, "Accept"); !errors.Is(r.err, io.EOF) {
		t.Fatalf("Accept = %v, want io.EOF", r.err)
	}
}

func TestListenerCloseDuringAdmission(t *testing.T) {
	for i := 0; i < 200; i++ {
		s := newSpawner()
		ln := listenSpawner(t, context.Background(), s)
		res := acceptAsync(ln)
		p := recv(t, s.started, "spawn")
		go p.peer.Write([]byte{1})
		ln.Close()
		r := recv(t, res, "Accept")
		switch {
		case r.err == nil:
			if p.killed.Load() != 0 {
				t.Fatal("accepted command killed")
			}
			r.conn.Close()
		case errors.Is(r.err, net.ErrClosed):
			recv(t, p.done, "reap")
			if p.killed.Load() != 1 {
				t.Fatalf("refused command killed %d times, want 1", p.killed.Load())
			}
		default:
			t.Fatalf("Accept = %v", r.err)
		}
		if s.count() != 1 {
			t.Fatalf("%d commands started, want 1", s.count())
		}
	}
}

// pipeDial stands in for a subprocess: the peer end is handed to the test, the dial ctx recorded.
func pipeDial(peers chan<- net.Conn, ctxs chan<- context.Context) Dial {
	return func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		if name != "fake" || len(args) != 2 || args[1] != "b" {
			return nil, errors.New("unexpected command")
		}
		local, peer := net.Pipe()
		peers <- peer
		ctxs <- ctx
		return local, nil
	}
}

func TestListenerAcceptKeepsFirstByte(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		peer := <-peers
		peer.Write([]byte("hello"))
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("read %q", got)
	}
}

func TestListenerCloseWhileWaitingFirstByte(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	peer := <-peers
	ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer Read = %v after Close, want EOF", err)
	}
	if ctx := <-ctxs; ctx.Err() == nil {
		t.Fatal("subprocess context not cancelled after Close")
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

func TestDialCloseCancelsCommand(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	conn, err := DialContext(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr() != testAddr {
		t.Fatalf("RemoteAddr = %v", conn.RemoteAddr())
	}
	<-peers
	ctx := <-ctxs
	if ctx.Err() != nil {
		t.Fatal("command context cancelled before Close")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("command context still alive after Close")
	}
}

func TestDialCloseLetsCommandExitBeforeCancel(t *testing.T) {
	var alive atomic.Bool
	dial := func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		local, _ := net.Pipe()
		return netutils.ConnWithCloser(local, func() error {
			alive.Store(ctx.Err() == nil)
			return local.Close()
		}), nil
	}
	conn, err := DialContext(context.Background(), dial, testAddr, testAddr, []string{"fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !alive.Load() {
		t.Fatal("command context cancelled before its stdio was closed")
	}
}

// exitDial wraps pipeDial so each conn's Close blocks until exit is closed, like a command that
// is still running; every start is reported on dials.
func exitDial(peers chan<- net.Conn, ctxs chan<- context.Context, dials chan<- struct{}, exit <-chan struct{}) Dial {
	dial := pipeDial(peers, ctxs)
	return func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		dials <- struct{}{}
		conn, err := dial(ctx, name, args...)
		if err != nil {
			return nil, err
		}
		return netutils.ConnWithCloser(conn, func() error {
			<-exit
			return conn.Close()
		}), nil
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

func TestListenerAcceptWaitsForPreviousConnClose(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 2), make(chan context.Context, 2)
	dials, exit := make(chan struct{}, 2), make(chan struct{})
	ln, err := Listen(context.Background(), exitDial(peers, ctxs, dials, exit), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for peer := range peers {
			peer.Write([]byte{1})
		}
	}()
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	<-dials
	second := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		second <- err
	}()
	closed := make(chan error, 1)
	go func() { closed <- first.Close() }()
	select {
	case <-dials:
		t.Fatal("next command started before the previous connection was released")
	case <-time.After(100 * time.Millisecond):
	}
	close(exit)
	if err := recv(t, closed, "Close"); err != nil {
		t.Fatal(err)
	}
	recv(t, dials, "next command")
	if err := recv(t, second, "second Accept"); err != nil {
		t.Fatal(err)
	}
	close(peers)
}

func TestListenerCloseInterruptsWaitForPreviousConn(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 2), make(chan context.Context, 2)
	dials, exit := make(chan struct{}, 2), make(chan struct{})
	ln, err := Listen(context.Background(), exitDial(peers, ctxs, dials, exit), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		peer := <-peers
		peer.Write([]byte{1})
	}()
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	<-dials
	second := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		second <- err
	}()
	closed := make(chan error, 1)
	go func() { closed <- first.Close() }()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, second, "second Accept"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want net.ErrClosed", err)
	}
	if len(dials) != 0 {
		t.Fatal("next command started after Close")
	}
	close(exit)
	if err := recv(t, closed, "Close"); err != nil {
		t.Fatal(err)
	}
}
