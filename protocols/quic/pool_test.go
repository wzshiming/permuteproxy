package quic_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/protocols/quic"
)

// exchanges fails unless a byte crosses from c to srv and one back.
func exchanges(t *testing.T, c, srv net.Conn) {
	t.Helper()
	for _, d := range []struct{ from, to net.Conn }{{c, srv}, {srv, c}} {
		if _, err := d.from.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		setDeadline(t, d.to.SetReadDeadline, time.Now().Add(10*time.Second))
		if _, err := io.ReadFull(d.to, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
}

// The memory network binds the listener's socket first, then a carrier for each connection dialed.
const listened, firstDialed, secondDialed = 0, 1, 2

// bound fails unless m has bound want sockets so far.
func bound(t *testing.T, m *memNet, want int, when string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if got := len(m.bound); got != want {
		t.Fatalf("%d sockets bound %s, want %d", got, when, want)
	}
}

// closeTransport closes tr as the owner of a built chain does.
func closeTransport(t *testing.T, tr permuteproxy.Transport) {
	t.Helper()
	if err := tr.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConnsOpenTogetherShareOneConnection(t *testing.T) {
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c1, srv1 := connected(t, ln, tr)
	c2, srv2 := connected(t, ln, tr)
	bound(t, mem, secondDialed, "after two dials")
	exchanges(t, c2, srv2)
	exchanges(t, c1, srv1)
	if c1.LocalAddr().String() != c2.LocalAddr().String() {
		t.Fatalf("conns of one connection are at %v and %v, want one address", c1.LocalAddr(), c2.LocalAddr())
	}
}

func TestASharedConnectionLastsUntilItsLastConnCloses(t *testing.T) {
	before := quicGoroutines()
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c1, srv1 := connected(t, ln, tr)
	c2, srv2 := connected(t, ln, tr)
	exchanges(t, c1, srv1)
	c1.Close()
	srv1.Close()
	exchanges(t, c2, srv2)
	if closes := mem.socket(t, firstDialed).closes.Load(); closes != 0 {
		t.Fatalf("carrier closed %d times while a conn is open on its connection, want 0", closes)
	}
	c2.Close()
	srv2.Close()
	eventuallyReleased(t, mem.socket(t, firstDialed), 5*time.Second, "shared")
	ln.Close()
	noGoroutinesLeft(t, before, time.Second)
}

func TestADialAfterTheLastConnClosedOpensAConnection(t *testing.T) {
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c1, srv1 := connected(t, ln, tr)
	exchanges(t, c1, srv1)
	c1.Close()
	srv1.Close()
	eventuallyReleased(t, mem.socket(t, firstDialed), 5*time.Second, "first")
	c2, srv2 := connected(t, ln, tr)
	exchanges(t, c2, srv2)
	bound(t, mem, secondDialed+1, "after a dial found no connection")
}

func TestADialAfterTheConnectionEndedOpensAConnection(t *testing.T) {
	mem := newMemNet()
	e := permuteproxy.Engine{Base: mem}
	ln, k := listenQUIC(t, e)
	tr := build(t, e, quicChain(ln.Addr().String(), k.client))
	c1, _ := connected(t, ln, tr)
	ln.Close()
	// The Read returns once the dialer has learned that the listener aborted the connection.
	setDeadline(t, c1.SetReadDeadline, time.Now().Add(10*time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read of a conn outlived its aborted connection")
	}
	again, err := build(t, e, quicChain(ln.Addr().String(), k.server)).Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	// c1 is still open, so the pool still has its connection when the next dial comes.
	c2, srv2 := connected(t, again, tr)
	exchanges(t, c2, srv2)
}

func TestAFullConnectionLeavesTheNextDialItsOwn(t *testing.T) {
	// The listener never ends its side of a stream, so no Close waits for it.
	quic.SetCloseWait(t, time.Millisecond)
	quic.SetLinger(t, time.Millisecond)
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	go func() {
		for {
			if _, err := ln.Accept(); err != nil {
				return
			}
		}
	}()
	for range quic.MaxStreams {
		dial(t, tr)
	}
	bound(t, mem, secondDialed, "while the connection has room")
	dial(t, tr)
	bound(t, mem, secondDialed+1, "after a dial past a full connection")
}

// closed closes both ends of a conn and waits until the dialed end has let go of its connection.
func closed(t *testing.T, c, srv net.Conn) {
	t.Helper()
	srv.Close()
	c.Close()
	// The dialed Close returns once the peer has ended its side, or by its short bound.
	time.Sleep(100 * time.Millisecond)
}

func TestAnIdleConnectionServesTheNextDial(t *testing.T) {
	before := quicGoroutines()
	quic.SetIdleKeep(t, time.Minute)
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c1, srv1 := connected(t, ln, tr)
	exchanges(t, c1, srv1)
	closed(t, c1, srv1)
	if closes := mem.socket(t, firstDialed).closes.Load(); closes != 0 {
		t.Fatalf("carrier closed %d times while its connection is kept idle, want 0", closes)
	}
	c2, srv2 := connected(t, ln, tr)
	exchanges(t, c2, srv2)
	bound(t, mem, secondDialed, "after a dial found the idle connection")
	closed(t, c2, srv2)
	closeTransport(t, tr)
	released(t, mem.socket(t, firstDialed), "idle")
	ln.Close()
	noGoroutinesLeft(t, before, time.Second)
}

func TestAnIdleConnectionIsReleasedAfterItsKeep(t *testing.T) {
	before := quicGoroutines()
	quic.SetIdleKeep(t, 300*time.Millisecond)
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, srv := connected(t, ln, tr)
	exchanges(t, c, srv)
	closed(t, c, srv)
	eventuallyReleased(t, mem.socket(t, firstDialed), 5*time.Second, "idle")
	c2, srv2 := connected(t, ln, tr)
	exchanges(t, c2, srv2)
	bound(t, mem, secondDialed+1, "after a dial found the connection released")
	closed(t, c2, srv2)
	eventuallyReleased(t, mem.socket(t, secondDialed), 5*time.Second, "second idle")
	ln.Close()
	noGoroutinesLeft(t, before, time.Second)
}

func TestAClosedTransportKeepsNoConnectionIdle(t *testing.T) {
	quic.SetIdleKeep(t, time.Minute)
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c, srv := connected(t, ln, tr)
	closeTransport(t, tr)
	// A conn open at the Close keeps its connection.
	exchanges(t, c, srv)
	closed(t, c, srv)
	eventuallyReleased(t, mem.socket(t, firstDialed), 5*time.Second, "dialed")
}
