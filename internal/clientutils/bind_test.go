package clientutils

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

// proxy answers BIND requests: each binds the port bound maps the asked address to, and accepts the peers sent to peers.
type proxy struct {
	bound func(address string) int
	asked chan string
	peers chan net.Addr
}

func (p *proxy) bind(_ context.Context, address string) (net.Conn, net.Addr, error) {
	p.asked <- address
	port := p.bound(address)
	if port < 0 {
		return nil, nil, errors.New("refused")
	}
	conn, _ := net.Pipe()
	return conn, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: port}, nil
}

func (p *proxy) wait(conn net.Conn) (net.Addr, error) {
	closed := make(chan struct{})
	go func() {
		conn.Read(make([]byte, 1))
		close(closed)
	}()
	select {
	case peer := <-p.peers:
		return peer, nil
	case <-closed:
		return nil, net.ErrClosed
	}
}

func listen(t *testing.T, address string, bound func(string) int) (*proxy, net.Listener) {
	t.Helper()
	p := &proxy{bound: bound, asked: make(chan string, 8), peers: make(chan net.Addr)}
	ln, err := ListenBind(context.Background(), address, p.bind, p.wait)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if got := <-p.asked; got != address {
		t.Fatalf("first request for %q, want %q", got, address)
	}
	return p, ln
}

func accept(t *testing.T, ln net.Listener) (net.Conn, error) {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	got := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		got <- result{conn, err}
	}()
	select {
	case r := <-got:
		return r.conn, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return")
		return nil, nil
	}
}

func TestListenBindAsksAgainAfterEachAccept(t *testing.T) {
	p, ln := listen(t, "10.0.0.1:80", func(string) int { return 80 })
	if got := ln.Addr().String(); got != "10.0.0.1:80" {
		t.Fatalf("Addr = %s, want 10.0.0.1:80", got)
	}
	for i := range 3 {
		peer := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1000 + i}
		p.peers <- peer
		conn, err := accept(t, ln)
		if err != nil {
			t.Fatal(err)
		}
		if conn.RemoteAddr() != net.Addr(peer) || conn.LocalAddr() != ln.Addr() {
			t.Fatalf("accepted %v -> %v, want %v -> %v", conn.RemoteAddr(), conn.LocalAddr(), peer, ln.Addr())
		}
		if got := <-p.asked; got != "10.0.0.1:80" {
			t.Fatalf("next request for %q, want 10.0.0.1:80", got)
		}
	}
}

func TestListenBindKeepsThePortAProxyChoseForPortZero(t *testing.T) {
	next := 5000
	// The proxy picks a new port for each request for port 0.
	p, ln := listen(t, ":0", func(address string) int {
		_, port, _ := net.SplitHostPort(address)
		if n, _ := strconv.Atoi(port); n != 0 {
			return n
		}
		next++
		return next
	})
	p.peers <- &net.TCPAddr{}
	if _, err := accept(t, ln); err != nil {
		t.Fatal(err)
	}
	if first, second := <-p.asked, <-p.asked; first != ":0" || second != ":5001" {
		t.Fatalf("next requests for %q and %q, want :0 and then :5001", first, second)
	}
	if got := ln.Addr().String(); got != "10.0.0.1:5001" {
		t.Fatalf("Addr = %s, want 10.0.0.1:5001", got)
	}
}

func TestListenBindFailsOnceTheProxyRefuses(t *testing.T) {
	requests := 0
	p, ln := listen(t, "10.0.0.1:80", func(string) int {
		if requests++; requests > 1 {
			return -1
		}
		return 80
	})
	p.peers <- &net.TCPAddr{}
	// The conn accepted before the refusal is still handed over.
	if _, err := accept(t, ln); err != nil {
		t.Fatal(err)
	}
	if _, err := accept(t, ln); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want the refusal", err)
	}
}

func TestListenBindCloseEndsAccept(t *testing.T) {
	_, ln := listen(t, "10.0.0.1:80", func(string) int { return 80 })
	failed := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		failed <- err
	}()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failed:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
	if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close = %v, want net.ErrClosed", err)
	}
}

func TestHandshakeFailsOnceCtxEnds(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	err := Handshake(ctx, conn, time.Minute, func() error {
		_, err := conn.Read(make([]byte, 1))
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Handshake = %v, want context.Canceled", err)
	}
}

// noDeadlineConn refuses deadlines, as an ssh channel does.
type noDeadlineConn struct{ net.Conn }

var errNoDeadline = errors.New("deadline not supported")

func (noDeadlineConn) SetDeadline(time.Time) error      { return errNoDeadline }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errNoDeadline }

func TestHandshakeSucceedsOnAConnWithoutDeadlines(t *testing.T) {
	inner, peer := net.Pipe()
	defer peer.Close()
	defer inner.Close()
	conn := noDeadlineConn{inner}
	go peer.Write([]byte{1})
	err := Handshake(context.Background(), conn, time.Minute, func() error {
		_, err := conn.Read(make([]byte, 1))
		return err
	})
	if err != nil {
		t.Fatalf("Handshake = %v, want nil", err)
	}
	// The conn stays usable after the handshake.
	go peer.Write([]byte{2})
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("Read after Handshake = %v", err)
	}
}

func TestHandshakeTimesOutOnAConnWithoutDeadlines(t *testing.T) {
	inner, peer := net.Pipe()
	defer peer.Close()
	defer inner.Close()
	conn := noDeadlineConn{inner}
	err := Handshake(context.Background(), conn, 50*time.Millisecond, func() error {
		_, err := conn.Read(make([]byte, 1))
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Handshake = %v, want context.DeadlineExceeded", err)
	}
}

func TestHandshakeLeavesNoDeadlineBehind(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	if err := Handshake(context.Background(), conn, 50*time.Millisecond, func() error { return nil }); err != nil {
		t.Fatalf("Handshake = %v, want nil", err)
	}
	time.AfterFunc(150*time.Millisecond, func() { peer.Write([]byte{1}) })
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("Read after the timeout passed = %v", err)
	}
}
