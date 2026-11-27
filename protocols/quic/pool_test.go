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

// The memory network binds the listener's socket first, then one carrier a dial.
const listened, firstDial, secondDial = 0, 1, 2

func TestConnsOpenTogetherShareOneConnection(t *testing.T) {
	mem := newMemNet()
	ln, tr := pair(t, permuteproxy.Engine{Base: mem})
	c1, srv1 := connected(t, ln, tr)
	c2, srv2 := connected(t, ln, tr)
	unsent(t, mem.socket(t, secondDial), "second dial's")
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
	if closes := mem.socket(t, firstDial).closes.Load(); closes != 0 {
		t.Fatalf("carrier closed %d times while a conn is open on its connection, want 0", closes)
	}
	c2.Close()
	srv2.Close()
	eventuallyReleased(t, mem.socket(t, firstDial), 5*time.Second, "shared")
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
	eventuallyReleased(t, mem.socket(t, firstDial), 5*time.Second, "first")
	c2, srv2 := connected(t, ln, tr)
	exchanges(t, c2, srv2)
	if writes := mem.socket(t, secondDial).writes.Load(); writes == 0 {
		t.Fatal("dial after the connection was released sent nothing on its own carrier")
	}
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
	for i := 1; i < quic.MaxStreams; i++ {
		unsent(t, mem.socket(t, firstDial+i), "sharing dial's")
	}
	dial(t, tr)
	if writes := mem.socket(t, firstDial+quic.MaxStreams).writes.Load(); writes == 0 {
		t.Fatal("dial past a full connection sent nothing on its own carrier")
	}
}
