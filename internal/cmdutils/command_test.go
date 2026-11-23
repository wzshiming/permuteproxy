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

// testExitGrace keeps the exit-output window short so probes of it stay bounded.
const testExitGrace = 50 * time.Millisecond

var errDeadline = errors.New("deadline unsupported")

// fakeProcess stands in for a command: the test drives peer, ends it with exit and sees Kill.
type fakeProcess struct {
	net.Conn
	peer      net.Conn
	ctx       context.Context
	done      chan struct{}
	closed    chan struct{}
	deadlines chan time.Time
	// failDeadline, when set, may refuse a read deadline; a refused one is not applied to the pipe.
	failDeadline func(time.Time) error
	once         sync.Once
	closeOnce    sync.Once
	err          error
	killed       atomic.Int32
	reading      atomic.Int32
}

func (p *fakeProcess) Read(b []byte) (int, error) {
	p.reading.Add(1)
	defer p.reading.Add(-1)
	return p.Conn.Read(b)
}

// SetReadDeadline reports t on deadlines once it has been applied or refused.
func (p *fakeProcess) SetReadDeadline(t time.Time) error {
	var err error
	if p.failDeadline != nil {
		err = p.failDeadline(t)
	}
	if err == nil {
		err = p.Conn.SetReadDeadline(t)
	}
	p.deadlines <- t
	return err
}

func (p *fakeProcess) Done() <-chan struct{} { return p.done }

func (p *fakeProcess) Err() error { return p.err }

func (p *fakeProcess) Kill() error {
	p.killed.Add(1)
	p.exit(errors.New("signal: killed"))
	return nil
}

func (p *fakeProcess) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return p.Conn.Close()
}

// exit ends the command: its output closes and it is reaped with err.
func (p *fakeProcess) exit(err error) {
	p.peer.Close()
	p.finish(err)
}

// finish reaps the command with err while its output stays open, as when a descendant inherited it.
func (p *fakeProcess) finish(err error) {
	p.once.Do(func() {
		p.err = err
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
	p := &fakeProcess{Conn: local, peer: peer, ctx: ctx, done: make(chan struct{}), closed: make(chan struct{}), deadlines: make(chan time.Time, 4)}
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
	ln, err := Listen(ctx, s.dial, testAddr, testAddr, []string{"fake"}, testExitGrace)
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
	if _, err := Listen(ctx, s.dial, testAddr, testAddr, []string{"fake"}, testExitGrace); !errors.Is(err, context.Canceled) {
		t.Fatalf("Listen = %v, want context.Canceled", err)
	}
	if s.count() != 0 {
		t.Fatal("command started under a canceled context")
	}
}

type ctxKey struct{}

// afterFuncCtx counts the AfterFunc registrations context.AfterFunc delegates to it and the stops.
type afterFuncCtx struct {
	context.Context
	done    chan struct{}
	added   atomic.Int32
	stopped atomic.Int32
}

func (c *afterFuncCtx) Done() <-chan struct{} { return c.done }

func (c *afterFuncCtx) AfterFunc(f func()) func() bool {
	c.added.Add(1)
	var once sync.Once
	return func() bool {
		stopped := false
		once.Do(func() {
			stopped = true
			c.stopped.Add(1)
		})
		return stopped
	}
}

func TestDialContextFailedStartReleasesCallerContext(t *testing.T) {
	ctx := &afterFuncCtx{Context: context.Background(), done: make(chan struct{})}
	fail := errors.New("no such command")
	dial := func(ctx context.Context, name string, args ...string) (net.Conn, error) { return nil, fail }
	for i := 0; i < 3; i++ {
		if _, err := DialContext(ctx, dial, testAddr, testAddr, []string{"fake"}); !errors.Is(err, fail) {
			t.Fatalf("DialContext = %v, want %v", err, fail)
		}
	}
	if ctx.added.Load() == 0 {
		t.Fatal("caller context's AfterFunc not used")
	}
	if added, stopped := ctx.added.Load(), ctx.stopped.Load(); stopped != added {
		t.Fatalf("failed starts left %d of %d AfterFunc registrations on the caller's context", added-stopped, added)
	}
}

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

func TestListenerCloseKillsSpawnAwaitingReap(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	res := acceptAsync(ln)
	p := recv(t, s.started, "spawn")
	p.peer.Close()
	recv(t, p.closed, "conn Close after EOF")
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if r := recv(t, res, "Accept"); !errors.Is(r.err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want net.ErrClosed", r.err)
	}
	recv(t, p.done, "reap")
	if p.killed.Load() != 1 {
		t.Fatalf("command lingering after EOF killed %d times by Close, want 1", p.killed.Load())
	}
}

func TestListenerRespawnsWhenExitedCommandLeavesStdoutOpen(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	res := acceptAsync(ln)
	first := recv(t, s.started, "spawn")
	first.finish(nil)
	second := recv(t, s.started, "respawn while a descendant holds stdout")
	go second.peer.Write([]byte{1})
	r := recv(t, res, "Accept")
	if r.err != nil {
		t.Fatal(r.err)
	}
	r.conn.Close()
	if first.killed.Load() != 0 {
		t.Fatal("cleanly exited command was killed")
	}
}

func TestListenerReportsFailedSpawnLeavingStdoutOpen(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	res := acceptAsync(ln)
	exitErr := errors.New("exit status 1")
	recv(t, s.started, "spawn").finish(exitErr)
	if r := recv(t, res, "Accept"); !errors.Is(r.err, exitErr) {
		t.Fatalf("Accept = %v, want %v", r.err, exitErr)
	}
	if s.count() != 1 {
		t.Fatalf("%d commands started, want 1", s.count())
	}
}

func TestListenerAcceptsOutputWrittenBeforeExit(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	res := acceptAsync(ln)
	p := recv(t, s.started, "spawn")
	p.finish(nil)
	go p.peer.Write([]byte{1})
	r := recv(t, res, "Accept")
	if r.err != nil {
		t.Fatalf("Accept = %v, want the byte written before exit", r.err)
	}
	defer r.conn.Close()
	if s.count() != 1 {
		t.Fatalf("%d commands started, want 1", s.count())
	}
	time.Sleep(testExitGrace + 100*time.Millisecond)
	go p.peer.Write([]byte("more"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(r.conn, buf); err != nil || string(buf) != "\x01more" {
		t.Fatalf("read %q, %v: accepted conn kept the exit deadline", buf, err)
	}
}

func TestListenerExitWindowFollowsConfig(t *testing.T) {
	s := newSpawner()
	ln := listenSpawner(t, context.Background(), s)
	defer ln.Close()
	res := acceptAsync(ln)
	p := recv(t, s.started, "spawn")
	before := time.Now()
	p.finish(nil)
	if d := recv(t, p.deadlines, "exit deadline"); d.Sub(before) < testExitGrace || d.Sub(before) > testExitGrace+500*time.Millisecond {
		t.Fatalf("exit deadline %v after exit, want the configured %v", d.Sub(before), testExitGrace)
	}
	if d := recv(t, p.deadlines, "deadline reset"); !d.IsZero() {
		t.Fatalf("read deadline left at %v before Accept, want zero", d)
	}
	second := recv(t, s.started, "respawn")
	go second.peer.Write([]byte{1})
	r := recv(t, res, "Accept")
	if r.err != nil {
		t.Fatal(r.err)
	}
	r.conn.Close()
}

func TestListenerReportsDeadlineErrorWithoutLeak(t *testing.T) {
	for name, fails := range map[string]func(time.Time) error{
		"set": func(time.Time) error { return errDeadline },
		"reset": func(d time.Time) error {
			if d.IsZero() {
				return errDeadline
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSpawner()
			ln := listenSpawner(t, context.Background(), s)
			defer ln.Close()
			res := acceptAsync(ln)
			p := recv(t, s.started, "spawn")
			p.failDeadline = fails
			p.finish(nil)
			if r := recv(t, res, "Accept"); !errors.Is(r.err, errDeadline) {
				t.Fatalf("Accept = %v, want %v", r.err, errDeadline)
			}
			recv(t, p.closed, "Close of the unaccepted command")
			if p.reading.Load() != 0 {
				t.Fatal("first-byte reader still running after Accept returned")
			}
			if s.count() != 1 {
				t.Fatalf("%d commands started, want 1", s.count())
			}
		})
	}
}

// A deadline refused because the conn is closed, as a pipe whose peer is gone refuses it, leaves
// the read to end by itself: a byte still opens the connection and EOF still starts over.
func TestListenerRefusedDeadlineKeepsRead(t *testing.T) {
	for _, tt := range []struct {
		name  string
		reset bool // refuse the reset to zero instead of the exit deadline
		data  bool // the peer sends a byte instead of closing
	}{
		{"set byte", false, true},
		{"set EOF", false, false},
		{"reset EOF", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newSpawner()
			ln := listenSpawner(t, context.Background(), s)
			defer ln.Close()
			res := acceptAsync(ln)
			p := recv(t, s.started, "spawn")
			p.failDeadline = func(d time.Time) error {
				if d.IsZero() == tt.reset {
					return io.ErrClosedPipe
				}
				return nil
			}
			p.finish(nil)
			recv(t, p.deadlines, "exit deadline")
			if tt.data {
				go p.peer.Write([]byte{1})
			} else {
				p.peer.Close()
				second := recv(t, s.started, "respawn after the clean exit")
				go second.peer.Write([]byte{1})
			}
			r := recv(t, res, "Accept")
			if r.err != nil {
				t.Fatalf("Accept = %v, want the read kept after the refused deadline", r.err)
			}
			r.conn.Close()
		})
	}
}

// eofConn is a command whose only output arrives together with its EOF.
type eofConn struct {
	net.Conn
	read atomic.Bool
}

func (c *eofConn) Read(b []byte) (int, error) {
	if c.read.CompareAndSwap(false, true) {
		b[0] = 'x'
		return 1, io.EOF
	}
	return 0, io.EOF
}

func TestListenerAcceptsFirstByteWithEOF(t *testing.T) {
	dial := func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		local, _ := net.Pipe()
		return &eofConn{Conn: local}, nil
	}
	ln, err := Listen(context.Background(), dial, testAddr, testAddr, []string{"fake"}, testExitGrace)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept = %v, want the byte that arrived with EOF", err)
	}
	defer conn.Close()
	if got, err := io.ReadAll(conn); err != nil || string(got) != "x" {
		t.Fatalf("read %q, %v, want \"x\" then EOF", got, err)
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
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"}, testExitGrace)
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
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"}, testExitGrace)
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
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"}, testExitGrace)
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
	ln, err := Listen(context.Background(), exitDial(peers, ctxs, dials, exit), testAddr, testAddr, []string{"fake", "a", "b"}, testExitGrace)
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
	ln, err := Listen(context.Background(), exitDial(peers, ctxs, dials, exit), testAddr, testAddr, []string{"fake", "a", "b"}, testExitGrace)
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
