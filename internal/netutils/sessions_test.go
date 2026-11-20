package netutils

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// pipeSession is one conn a pipeDialer handed out: the peer it was dialed for and the far end.
type pipeSession struct {
	peer   net.Addr
	conn   *trackedConn
	remote net.Conn
	got    chan string
}

// trackedConn counts Writes and signals Close; a non-nil readErr replaces any error Read returns, a non-nil writeErr fails every Write.
type trackedConn struct {
	net.Conn
	readErr  error
	writeErr error
	writes   atomic.Int32
	closed   chan struct{}
	once     sync.Once
}

func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && c.readErr != nil {
		err = c.readErr
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(b)
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// pipeDialer dials net.Pipe pairs whose far end, unless mute, collects each Read into got.
// hold, when set, runs first and fails the dial with the error it returns.
type pipeDialer struct {
	hold     func(ctx context.Context, peer net.Addr) error
	readErr  error
	writeErr error
	mute     bool
	dials    atomic.Int32
	sessions chan *pipeSession
}

func newPipeDialer() *pipeDialer {
	return &pipeDialer{sessions: make(chan *pipeSession, 128)}
}

func (d *pipeDialer) dial(ctx context.Context, peer net.Addr) (net.Conn, error) {
	d.dials.Add(1)
	if d.hold != nil {
		if err := d.hold(ctx, peer); err != nil {
			return nil, err
		}
	}
	local, remote := net.Pipe()
	s := &pipeSession{
		peer:   peer,
		conn:   &trackedConn{Conn: local, readErr: d.readErr, writeErr: d.writeErr, closed: make(chan struct{})},
		remote: remote,
		got:    make(chan string, 64),
	}
	if !d.mute {
		go s.collect()
	}
	d.sessions <- s
	return s.conn, nil
}

func (s *pipeSession) collect() {
	defer close(s.got)
	buf := make([]byte, 128<<10)
	for {
		n, err := s.remote.Read(buf)
		if err != nil {
			return
		}
		s.got <- string(buf[:n])
	}
}

// next waits for the session dialed next.
func (d *pipeDialer) next(t *testing.T) *pipeSession {
	t.Helper()
	select {
	case s := <-d.sessions:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was dialed")
	}
	return nil
}

// recv waits for the next chunk the far end read.
func (s *pipeSession) recv(t *testing.T) string {
	t.Helper()
	select {
	case got, ok := <-s.got:
		if !ok {
			t.Fatalf("session to %v closed", s.peer)
		}
		return got
	case <-time.After(5 * time.Second):
		t.Fatalf("session to %v got nothing", s.peer)
	}
	return ""
}

func (s *pipeSession) expect(t *testing.T, want string) {
	t.Helper()
	if got := s.recv(t); got != want {
		t.Fatalf("session to %v got %q, want %q", s.peer, got, want)
	}
}

func (s *pipeSession) isClosed() bool {
	select {
	case <-s.conn.closed:
		return true
	default:
		return false
	}
}

func writeTo(t *testing.T, pc net.PacketConn, b string, peer net.Addr) {
	t.Helper()
	if n, err := pc.WriteTo([]byte(b), peer); n != len(b) || err != nil {
		t.Fatalf("WriteTo(%q, %v) = %d, %v", b, peer, n, err)
	}
}

// readFrom waits for one ReadFrom into a buffer of size bytes.
func readFrom(t *testing.T, pc net.PacketConn, size int) (string, net.Addr) {
	t.Helper()
	r := wait(t, goReadFrom(pc, size), "ReadFrom")
	if r.err != nil {
		t.Fatalf("ReadFrom = %v", r.err)
	}
	return r.b, r.from
}

type readResult struct {
	b    string
	from net.Addr
	err  error
}

// goReadFrom starts one ReadFrom into a buffer of size bytes and delivers its result.
func goReadFrom(pc net.PacketConn, size int) <-chan readResult {
	c := make(chan readResult, 1)
	go func() {
		buf := make([]byte, size)
		n, from, err := pc.ReadFrom(buf)
		c <- readResult{string(buf[:n]), from, err}
	}()
	return c
}

// goWriteTo starts one WriteTo and delivers its error.
func goWriteTo(pc net.PacketConn, b string, peer net.Addr) <-chan error {
	c := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte(b), peer)
		c <- err
	}()
	return c
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

// wait receives from c, failing the test if nothing arrives.
func wait[T any](t *testing.T, c <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never returned", what)
	}
	var zero T
	return zero
}

func testPeer(i int) net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i)), Port: 53}
}

func TestSessionsDialEachPeerOnFirstWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		if n := d.dials.Load(); n != 0 {
			t.Fatalf("NewSessions dialed %d times before any write", n)
		}
		peer := NewNetAddr("udp", "192.0.2.1:53")
		writeTo(t, pc, "one", peer)
		s := d.next(t)
		if s.peer != peer {
			t.Fatalf("dialed %v, want the written-to %v", s.peer, peer)
		}
		s.expect(t, "one")
		writeTo(t, pc, "two", testPeer(1))
		s.expect(t, "two")
		other := NewNetAddr("unixgram", peer.String())
		writeTo(t, pc, "three", other)
		o := d.next(t)
		o.expect(t, "three")
		if n := d.dials.Load(); n != 2 {
			t.Fatalf("dialed %d times, want once per network and address", n)
		}
		if a, b := s.conn.writes.Load(), o.conn.writes.Load(); a != 2 || b != 1 {
			t.Fatalf("sessions got %d and %d writes, want one per WriteTo", a, b)
		}
	})
}

func TestSessionsConcurrentFirstWritesShareOneDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		d := newPipeDialer()
		d.hold = func(context.Context, net.Addr) error {
			<-release
			return nil
		}
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		var wg sync.WaitGroup
		for _, b := range []string{"a", "b"} {
			wg.Go(func() {
				if _, err := pc.WriteTo([]byte(b), testPeer(1)); err != nil {
					t.Errorf("WriteTo(%q) = %v", b, err)
				}
			})
		}
		synctest.Wait()
		if n := d.dials.Load(); n != 1 {
			t.Fatalf("concurrent first writes dialed %d times, want once", n)
		}
		close(release)
		wg.Wait()
		s := d.next(t)
		got := []string{s.recv(t), s.recv(t)}
		slices.Sort(got)
		if !slices.Equal(got, []string{"a", "b"}) {
			t.Fatalf("session got %q, want both writes", got)
		}
	})
}

func TestSessionsDialErrorLeavesNoSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		refused := errors.New("refused")
		d := newPipeDialer()
		d.hold = func(context.Context, net.Addr) error {
			if d.dials.Load() == 1 {
				return refused
			}
			return nil
		}
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		if n, err := pc.WriteTo([]byte("lost"), testPeer(1)); n != 0 || !errors.Is(err, refused) {
			t.Fatalf("WriteTo through a failing dial = %d, %v, want %v", n, err, refused)
		}
		writeTo(t, pc, "retry", testPeer(1))
		d.next(t).expect(t, "retry")
		if n := d.dials.Load(); n != 2 {
			t.Fatalf("dialed %d times, want the failed dial retried", n)
		}
	})
}

func TestSessionsDialErrorReachesWaitingWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		refused := errors.New("refused")
		release := make(chan struct{})
		d := newPipeDialer()
		d.hold = func(context.Context, net.Addr) error {
			<-release
			return refused
		}
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		writes := []<-chan error{goWriteTo(pc, "a", testPeer(1)), goWriteTo(pc, "b", testPeer(1))}
		synctest.Wait()
		close(release)
		for _, write := range writes {
			if err := wait(t, write, "WriteTo"); !errors.Is(err, refused) {
				t.Fatalf("WriteTo sharing a failed dial = %v, want %v", err, refused)
			}
		}
	})
}

func TestSessionsWriteToNilAddrFails(t *testing.T) {
	d := newPipeDialer()
	pc := NewSessions(d.dial, SessionOptions{})
	defer pc.Close()
	if n, err := pc.WriteTo([]byte("x"), nil); n != 0 || err == nil {
		t.Fatalf("WriteTo(nil) = %d, %v, want an error", n, err)
	}
	if n := d.dials.Load(); n != 0 {
		t.Fatalf("WriteTo(nil) dialed %d times", n)
	}
}

func TestSessionsLocalAddrIsZeroUDP(t *testing.T) {
	pc := NewSessions(newPipeDialer().dial, SessionOptions{})
	defer pc.Close()
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP != nil || addr.Port != 0 || addr.Zone != "" {
		t.Fatalf("LocalAddr() = %#v, want a zero *net.UDPAddr", pc.LocalAddr())
	}
}

func TestSessionsReadFromOneChunkPerRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		peer := NewNetAddr("udp", "192.0.2.1:53")
		writeTo(t, pc, "open", peer)
		writeTo(t, pc, "same", testPeer(1))
		s := d.next(t)
		chunks := []string{"hello", "world", strings.Repeat("x", 64<<10)}
		go func() {
			for _, b := range chunks {
				s.remote.Write([]byte(b))
			}
		}()
		for _, want := range chunks {
			got, from := readFrom(t, pc, 128<<10)
			if got != want {
				t.Fatalf("ReadFrom = %d bytes, want the %d-byte chunk", len(got), len(want))
			}
			if from != peer {
				t.Fatalf("ReadFrom tagged %v, want the address the session was opened with", from)
			}
		}
	})
}

func TestSessionsReadFromTagsEachSessionsPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		want := map[string]net.Addr{}
		for i := 1; i <= 2; i++ {
			peer := testPeer(i)
			writeTo(t, pc, "open", peer)
			s := d.next(t)
			payload := "from " + peer.String()
			want[payload] = peer
			go s.remote.Write([]byte(payload))
		}
		for range want {
			got, from := readFrom(t, pc, 64)
			if peer, ok := want[got]; !ok || from != peer {
				t.Fatalf("ReadFrom = %q from %v", got, from)
			}
			delete(want, got)
		}
	})
}

func TestSessionsReadFromTruncatesLongChunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		writeTo(t, pc, "open", testPeer(1))
		s := d.next(t)
		go func() {
			s.remote.Write([]byte("0123456789"))
			s.remote.Write([]byte("next"))
		}()
		if got, _ := readFrom(t, pc, 4); got != "0123" {
			t.Fatalf("ReadFrom into 4 bytes = %q, want \"0123\"", got)
		}
		if got, _ := readFrom(t, pc, 64); got != "next" {
			t.Fatalf("ReadFrom after a truncated chunk = %q, want the next chunk", got)
		}
	})
}

func TestSessionsReaderWaitsForReadFrom(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		writeTo(t, pc, "open", testPeer(1))
		s := d.next(t)
		go func() {
			s.remote.Write([]byte("first"))
			s.remote.Write([]byte("second"))
		}()
		synctest.Wait()
		for _, want := range []string{"first", "second"} {
			if got, _ := readFrom(t, pc, 64); got != want {
				t.Fatalf("ReadFrom = %q, want %q", got, want)
			}
		}
	})
}

func TestSessionsCloseUnblocksReadFrom(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		writeTo(t, pc, "open", testPeer(1))
		read := goReadFrom(pc, 64)
		synctest.Wait()
		if err := pc.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if r := wait(t, read, "ReadFrom blocked at Close"); !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("ReadFrom blocked at Close = %v, want net.ErrClosed", r.err)
		}
		if _, _, err := pc.ReadFrom(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
		}
		for _, peer := range []net.Addr{testPeer(1), testPeer(2)} {
			if _, err := pc.WriteTo([]byte("late"), peer); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("WriteTo(%v) after Close = %v, want net.ErrClosed", peer, err)
			}
		}
		if n := d.dials.Load(); n != 1 {
			t.Fatalf("dialed %d times, want no dial after Close", n)
		}
		if err := pc.Close(); err != nil {
			t.Fatalf("second Close = %v", err)
		}
	})
}

// TestSessionsCloseReleasesSessions leaves synctest to fail on any goroutine Close leaves behind.
func TestSessionsCloseReleasesSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slow := testPeer(9)
		dialing := make(chan context.Context, 1)
		d := newPipeDialer()
		d.mute = true
		d.hold = func(ctx context.Context, peer net.Addr) error {
			if peer != slow {
				return nil
			}
			dialing <- ctx
			<-ctx.Done()
			return ctx.Err()
		}
		pc := NewSessions(d.dial, SessionOptions{})
		writes := []<-chan error{goWriteTo(pc, "stuck", testPeer(1)), goWriteTo(pc, "stuck", slow)}
		s := d.next(t)
		go s.remote.Write([]byte("unread"))
		ctx := wait(t, dialing, "dial")
		synctest.Wait()
		if err := pc.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		for _, write := range writes {
			if err := wait(t, write, "WriteTo blocked at Close"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("WriteTo blocked at Close = %v, want net.ErrClosed", err)
			}
		}
		if ctx.Err() == nil {
			t.Fatal("Close left the in-flight dial's context live")
		}
		if !s.isClosed() {
			t.Fatal("Close left a session conn open")
		}
	})
}

// lingeringConn returns from a Read that Close interrupted only a second later.
type lingeringConn struct {
	net.Conn
	returned atomic.Bool
}

func (c *lingeringConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		time.Sleep(time.Second)
		c.returned.Store(true)
	}
	return n, err
}

func TestSessionsCloseWaitsForSessionReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conns := make(chan *lingeringConn, 1)
		pc := NewSessions(func(context.Context, net.Addr) (net.Conn, error) {
			local, remote := net.Pipe()
			go io.Copy(io.Discard, remote)
			c := &lingeringConn{Conn: local}
			conns <- c
			return c, nil
		}, SessionOptions{})
		writeTo(t, pc, "open", testPeer(1))
		c := <-conns
		pc.Close()
		if !c.returned.Load() {
			t.Fatal("Close returned while a session conn was still inside Read")
		}
	})
}

// slowClosingConn takes half a second to close.
type slowClosingConn struct{ net.Conn }

func (c slowClosingConn) Close() error {
	time.Sleep(500 * time.Millisecond)
	return c.Conn.Close()
}

func TestSessionsCloseClosesSessionConnsConcurrently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pc := NewSessions(func(context.Context, net.Addr) (net.Conn, error) {
			local, remote := net.Pipe()
			go io.Copy(io.Discard, remote)
			return slowClosingConn{local}, nil
		}, SessionOptions{})
		for i := 1; i <= 16; i++ {
			writeTo(t, pc, "open", testPeer(i))
		}
		start := time.Now()
		if err := pc.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("Close of 16 sessions whose conns take 500ms each to close took %v, want about 500ms", took)
		}
	})
}

func TestSessionsCloseWinsOverExpiredDeadline(t *testing.T) {
	pc := NewSessions(newPipeDialer().dial, SessionOptions{})
	pc.SetDeadline(time.Now())
	pc.Close()
	for range 20 {
		if _, _, err := pc.ReadFrom(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close past the deadline = %v, want net.ErrClosed", err)
		}
		if _, err := pc.WriteTo([]byte("x"), testPeer(1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("WriteTo after Close past the deadline = %v, want net.ErrClosed", err)
		}
	}
}

func TestSessionsConcurrentUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		echo := func(_ context.Context, _ net.Addr) (net.Conn, error) {
			local, remote := net.Pipe()
			go func() {
				buf := make([]byte, 64)
				for {
					n, err := remote.Read(buf)
					if err != nil {
						return
					}
					if _, err := remote.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
			return local, nil
		}
		pc := NewSessions(echo, SessionOptions{})
		var wg sync.WaitGroup
		for i := 1; i <= 4; i++ {
			peer := testPeer(i)
			wg.Go(func() {
				for {
					_, err := pc.WriteTo([]byte(peer.String()), peer)
					if errors.Is(err, net.ErrClosed) {
						return
					}
					if err != nil {
						t.Errorf("WriteTo(%v) = %v", peer, err)
						return
					}
				}
			})
		}
		enough := make(chan struct{})
		wg.Go(func() {
			buf := make([]byte, 64)
			for i := 0; ; i++ {
				if i == 100 {
					close(enough)
				}
				n, from, err := pc.ReadFrom(buf)
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if err != nil || from == nil || string(buf[:n]) != from.String() {
					t.Errorf("ReadFrom = %q from %v, %v", buf[:n], from, err)
					return
				}
			}
		})
		wait(t, enough, "echo")
		if err := pc.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		wg.Wait()
	})
}

// quiet lets d pass without traffic, then lets the bubble settle.
func quiet(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

func TestSessionsIdleTimeoutCountsFromLastActivity(t *testing.T) {
	for _, tt := range []struct {
		opts SessionOptions
		idle time.Duration
	}{
		{SessionOptions{}, time.Minute},
		{SessionOptions{IdleTimeout: 10 * time.Second}, 10 * time.Second},
	} {
		t.Run(tt.idle.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newPipeDialer()
				pc := NewSessions(d.dial, tt.opts)
				defer pc.Close()
				peer := testPeer(1)
				writeTo(t, pc, "open", peer)
				s := d.next(t)
				s.expect(t, "open")
				quiet(tt.idle - time.Second)
				if s.isClosed() {
					t.Fatal("session closed before the idle timeout")
				}
				writeTo(t, pc, "write", peer)
				s.expect(t, "write")
				quiet(tt.idle - time.Second)
				if s.isClosed() {
					t.Fatal("session closed within the idle timeout of a write")
				}
				go s.remote.Write([]byte("read"))
				if got, _ := readFrom(t, pc, 64); got != "read" {
					t.Fatalf("ReadFrom = %q", got)
				}
				quiet(tt.idle - time.Second)
				if s.isClosed() {
					t.Fatal("session closed within the idle timeout of a read")
				}
				read := goReadFrom(pc, 64)
				quiet(2 * time.Second)
				if !s.isClosed() {
					t.Fatal("session stayed open past the idle timeout")
				}
				select {
				case r := <-read:
					t.Fatalf("idle close surfaced in ReadFrom: %q, %v", r.b, r.err)
				default:
				}
				writeTo(t, pc, "again", peer)
				again := d.next(t)
				again.expect(t, "again")
				go again.remote.Write([]byte("back"))
				if r := wait(t, read, "ReadFrom"); r.b != "back" || r.err != nil {
					t.Fatalf("ReadFrom = %q, %v, want \"back\" from the new session", r.b, r.err)
				}
			})
		})
	}
}

func TestSessionsEndedSessionIsForgotten(t *testing.T) {
	for name, readErr := range map[string]error{"EOF": nil, "read error": errors.New("broken")} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newPipeDialer()
				d.readErr = readErr
				pc := NewSessions(d.dial, SessionOptions{})
				defer pc.Close()
				read := goReadFrom(pc, 64)
				writeTo(t, pc, "open", testPeer(1))
				s := d.next(t)
				s.remote.Close()
				synctest.Wait()
				if !s.isClosed() {
					t.Fatal("session whose conn ended stayed open")
				}
				select {
				case r := <-read:
					t.Fatalf("ended session surfaced in ReadFrom: %q, %v", r.b, r.err)
				default:
				}
				writeTo(t, pc, "again", testPeer(1))
				again := d.next(t)
				again.expect(t, "again")
				go again.remote.Write([]byte("back"))
				if r := wait(t, read, "ReadFrom"); r.b != "back" || r.err != nil {
					t.Fatalf("ReadFrom = %q, %v, want \"back\" from the new session", r.b, r.err)
				}
			})
		})
	}
}

func TestSessionsWriteErrorDropsSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		broken := errors.New("write side closed")
		d := newPipeDialer()
		d.writeErr = broken
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		if _, err := pc.WriteTo([]byte("lost"), testPeer(1)); !errors.Is(err, broken) {
			t.Fatalf("WriteTo through a conn whose writes fail = %v, want %v", err, broken)
		}
		if !d.next(t).isClosed() {
			t.Fatal("a session whose Write failed stayed open while its Read was blocked")
		}
		d.writeErr = nil
		writeTo(t, pc, "again", testPeer(1))
		d.next(t).expect(t, "again")
		if n := d.dials.Load(); n != 2 {
			t.Fatalf("dialed %d times, want the failed session dialed anew", n)
		}
	})
}

func TestSessionsDialContextLivesWithItsSession(t *testing.T) {
	for _, tt := range []struct {
		name string
		end  func(t *testing.T, pc net.PacketConn)
	}{
		{"idle timeout", func(*testing.T, net.PacketConn) { quiet(10 * time.Second) }},
		{"eviction", func(t *testing.T, pc net.PacketConn) { writeTo(t, pc, "newer", testPeer(2)) }},
		{"Close", func(_ *testing.T, pc net.PacketConn) { pc.Close() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dialed := make(chan context.Context, 2)
				d := newPipeDialer()
				d.hold = func(ctx context.Context, _ net.Addr) error {
					dialed <- ctx
					return nil
				}
				pc := NewSessions(d.dial, SessionOptions{IdleTimeout: 10 * time.Second, MaxSessions: 1})
				defer pc.Close()
				pc.SetWriteDeadline(time.Now().Add(time.Second))
				writeTo(t, pc, "open", testPeer(1))
				ctx := wait(t, dialed, "dial")
				d.next(t).expect(t, "open")
				quiet(2 * time.Second)
				if ctx.Err() != nil {
					t.Fatal("the dial context ended while its session was open, past the write deadline")
				}
				pc.SetWriteDeadline(time.Time{})
				tt.end(t, pc)
				synctest.Wait()
				if ctx.Err() == nil {
					t.Fatal("the dial context outlived its session")
				}
			})
		})
	}
}

func TestSessionsEvictLeastRecentlyActive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var opened []*pipeSession
		d := newPipeDialer()
		d.hold = func(context.Context, net.Addr) error {
			n := 0
			for _, s := range opened {
				if !s.isClosed() {
					n++
				}
			}
			if n >= 2 {
				t.Errorf("dialing with %d sessions open, want one closed first", n)
			}
			return nil
		}
		pc := NewSessions(d.dial, SessionOptions{MaxSessions: 2})
		defer pc.Close()
		open := func(i int) *pipeSession {
			writeTo(t, pc, "open", testPeer(i))
			s := d.next(t)
			opened = append(opened, s)
			return s
		}
		s1, s2 := open(1), open(2)
		writeTo(t, pc, "again", s1.peer)
		s3 := open(3)
		if !s2.isClosed() || s1.isClosed() {
			t.Fatalf("closed first %v, second %v; want only the one written to least recently", s1.isClosed(), s2.isClosed())
		}
		go s1.remote.Write([]byte("read"))
		readFrom(t, pc, 64)
		s4 := open(4)
		if !s3.isClosed() || s1.isClosed() || s4.isClosed() {
			t.Fatal("a read did not count as activity for eviction")
		}
	})
}

func TestSessionsCapDefaultsTo64(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		var opened []*pipeSession
		for i := range 65 {
			writeTo(t, pc, "open", testPeer(i))
			opened = append(opened, d.next(t))
		}
		for i, s := range opened {
			if s.isClosed() != (i == 0) {
				t.Fatalf("session %d closed = %v, want only the first of 65 closed", i, s.isClosed())
			}
		}
	})
}

func TestSessionsCapCountsDialsInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slow := testPeer(1)
		dialing := make(chan context.Context, 1)
		d := newPipeDialer()
		d.hold = func(ctx context.Context, peer net.Addr) error {
			if peer != slow {
				return nil
			}
			dialing <- ctx
			<-ctx.Done()
			return ctx.Err()
		}
		pc := NewSessions(d.dial, SessionOptions{MaxSessions: 1})
		defer pc.Close()
		write := goWriteTo(pc, "slow", slow)
		ctx := wait(t, dialing, "dial")
		writeTo(t, pc, "fast", testPeer(2))
		d.next(t).expect(t, "fast")
		if ctx.Err() == nil {
			t.Fatal("a dial in flight survived a newer session over the cap")
		}
		if err := wait(t, write, "evicted WriteTo"); err == nil || errors.Is(err, net.ErrClosed) {
			t.Fatalf("evicted WriteTo = %v, want an error other than net.ErrClosed", err)
		}
	})
}

func TestSessionsLateDialIsDiscarded(t *testing.T) {
	for _, tt := range []struct {
		name     string
		overtake func(t *testing.T, pc net.PacketConn)
		closed   bool
	}{
		{"Close", func(_ *testing.T, pc net.PacketConn) { pc.Close() }, true},
		{"eviction", func(t *testing.T, pc net.PacketConn) { writeTo(t, pc, "newer", testPeer(2)) }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				late := testPeer(1)
				release := make(chan struct{})
				d := newPipeDialer()
				d.hold = func(_ context.Context, peer net.Addr) error {
					if peer == late {
						<-release
					}
					return nil
				}
				pc := NewSessions(d.dial, SessionOptions{MaxSessions: 1})
				defer pc.Close()
				write := goWriteTo(pc, "late", late)
				synctest.Wait()
				tt.overtake(t, pc)
				close(release)
				err := wait(t, write, "WriteTo")
				if err == nil || errors.Is(err, net.ErrClosed) != tt.closed {
					t.Fatalf("WriteTo whose dial outlived its session = %v, want net.ErrClosed only after Close", err)
				}
				var s *pipeSession
				for s == nil {
					if next := d.next(t); next.peer == late {
						s = next
					}
				}
				if !s.isClosed() {
					t.Fatal("a conn dialed after its session ended stayed open")
				}
			})
		})
	}
}

func TestSessionsReadDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		writeTo(t, pc, "open", testPeer(1))
		s := d.next(t)
		start := time.Now()
		pc.SetReadDeadline(start.Add(time.Second))
		if r := wait(t, goReadFrom(pc, 64), "ReadFrom"); !isTimeout(r.err) || time.Since(start) != time.Second {
			t.Fatalf("ReadFrom = %v after %v, want a timeout after 1s", r.err, time.Since(start))
		}
		pc.SetReadDeadline(time.Time{})
		go s.remote.Write([]byte("cleared"))
		if got, _ := readFrom(t, pc, 64); got != "cleared" {
			t.Fatalf("ReadFrom after clearing the deadline = %q", got)
		}
		start = time.Now()
		pc.SetReadDeadline(start.Add(time.Second))
		read := goReadFrom(pc, 64)
		quiet(time.Second / 2)
		pc.SetReadDeadline(start.Add(2 * time.Second))
		if r := wait(t, read, "ReadFrom"); !isTimeout(r.err) || time.Since(start) != 2*time.Second {
			t.Fatalf("ReadFrom = %v after %v, want a timeout at the extended 2s", r.err, time.Since(start))
		}
		pc.SetReadDeadline(time.Now().Add(time.Hour))
		go s.remote.Write([]byte("extended"))
		if got, _ := readFrom(t, pc, 64); got != "extended" {
			t.Fatalf("ReadFrom after extending an expired deadline = %q", got)
		}
		read = goReadFrom(pc, 64)
		synctest.Wait()
		pc.SetReadDeadline(time.Now())
		if r := wait(t, read, "ReadFrom"); !isTimeout(r.err) {
			t.Fatalf("ReadFrom blocked when the deadline moved to now = %v, want a timeout", r.err)
		}
	})
}

func TestSessionsWriteDeadlineBoundsDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialing := make(chan context.Context, 1)
		d := newPipeDialer()
		d.hold = func(ctx context.Context, _ net.Addr) error {
			if d.dials.Load() > 1 {
				return nil
			}
			dialing <- ctx
			<-ctx.Done()
			return ctx.Err()
		}
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		start := time.Now()
		pc.SetWriteDeadline(start.Add(time.Second))
		if err := wait(t, goWriteTo(pc, "slow", testPeer(1)), "WriteTo"); !isTimeout(err) || time.Since(start) != time.Second {
			t.Fatalf("WriteTo through a stalled dial = %v after %v, want a timeout after 1s", err, time.Since(start))
		}
		if ctx := wait(t, dialing, "dial"); ctx.Err() == nil {
			t.Fatal("the dial's context outlived the write deadline")
		}
		if _, err := pc.WriteTo([]byte("late"), testPeer(1)); !isTimeout(err) || d.dials.Load() != 1 {
			t.Fatalf("WriteTo past the deadline = %v after %d dials, want a timeout without a dial", err, d.dials.Load())
		}
		pc.SetWriteDeadline(time.Time{})
		writeTo(t, pc, "cleared", testPeer(1))
		d.next(t).expect(t, "cleared")
	})
}

func TestSessionsWriteDeadlineBoundsWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		d.mute = true
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		start := time.Now()
		pc.SetWriteDeadline(start.Add(time.Second))
		if err := wait(t, goWriteTo(pc, "stuck", testPeer(1)), "WriteTo"); !isTimeout(err) || time.Since(start) != time.Second {
			t.Fatalf("WriteTo a far end that never reads = %v after %v, want a timeout after 1s", err, time.Since(start))
		}
		s := d.next(t)
		go s.collect()
		pc.SetWriteDeadline(time.Now().Add(time.Hour))
		writeTo(t, pc, "through", testPeer(1))
		s.expect(t, "through")
		write := goWriteTo(pc, "stuck", testPeer(2))
		synctest.Wait()
		pc.SetWriteDeadline(time.Now())
		if err := wait(t, write, "WriteTo"); !isTimeout(err) {
			t.Fatalf("WriteTo blocked when the deadline moved to now = %v, want a timeout", err)
		}
		if n := d.dials.Load(); n != 2 {
			t.Fatalf("dialed %d times, want the timed-out session kept", n)
		}
	})
}

func TestSessionsSetDeadlineSetsBoth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		pc.SetDeadline(time.Now())
		if r := wait(t, goReadFrom(pc, 64), "ReadFrom"); !isTimeout(r.err) {
			t.Fatalf("ReadFrom past SetDeadline = %v, want a timeout", r.err)
		}
		if err := wait(t, goWriteTo(pc, "x", testPeer(1)), "WriteTo"); !isTimeout(err) {
			t.Fatalf("WriteTo past SetDeadline = %v, want a timeout", err)
		}
		pc.SetDeadline(time.Time{})
		writeTo(t, pc, "x", testPeer(1))
		s := d.next(t)
		s.expect(t, "x")
		go s.remote.Write([]byte("y"))
		if got, _ := readFrom(t, pc, 64); got != "y" {
			t.Fatalf("ReadFrom after clearing SetDeadline = %q", got)
		}
	})
}

func TestSessionsExpiredReadDeadlineWinsOverWaitingChunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newPipeDialer()
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		writeTo(t, pc, "open", testPeer(1))
		s := d.next(t)
		go s.remote.Write([]byte("waiting"))
		synctest.Wait()
		pc.SetReadDeadline(time.Now())
		for range 20 {
			if _, _, err := pc.ReadFrom(make([]byte, 64)); !isTimeout(err) {
				t.Fatalf("ReadFrom past its deadline with a chunk waiting = %v, want a timeout", err)
			}
		}
		pc.SetReadDeadline(time.Time{})
		if got, _ := readFrom(t, pc, 64); got != "waiting" {
			t.Fatalf("ReadFrom after clearing the deadline = %q, want the waiting chunk", got)
		}
	})
}

func TestSessionsWriteDeadlineSetDuringDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialing := make(chan context.Context, 1)
		d := newPipeDialer()
		d.hold = func(ctx context.Context, _ net.Addr) error {
			dialing <- ctx
			<-ctx.Done()
			return ctx.Err()
		}
		pc := NewSessions(d.dial, SessionOptions{})
		defer pc.Close()
		write := goWriteTo(pc, "slow", testPeer(1))
		ctx := wait(t, dialing, "dial")
		pc.SetWriteDeadline(time.Now())
		if err := wait(t, write, "WriteTo"); !isTimeout(err) || ctx.Err() == nil {
			t.Fatalf("WriteTo whose deadline passed during its dial = %v, want a timeout and the dial canceled", err)
		}
	})
}

func TestSessionsDeadlineClearedThenSetAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pc := NewSessions(newPipeDialer().dial, SessionOptions{})
		defer pc.Close()
		start := time.Now()
		pc.SetReadDeadline(start.Add(time.Hour))
		pc.SetReadDeadline(time.Time{})
		pc.SetReadDeadline(start.Add(time.Second))
		if r := wait(t, goReadFrom(pc, 64), "ReadFrom"); !isTimeout(r.err) || time.Since(start) != time.Second {
			t.Fatalf("ReadFrom = %v after %v, want a timeout after 1s", r.err, time.Since(start))
		}
	})
}
