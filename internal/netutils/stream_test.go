package netutils

import (
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

var streamPeer = NewNetAddr("udp", "192.0.2.1:53")

// recordConn records the Read and Write calls a wrapper makes; Read answers with reply.
type recordConn struct {
	net.Conn
	reply  string
	reads  [][]byte
	writes []string
}

func (c *recordConn) Read(b []byte) (int, error) {
	c.reads = append(c.reads, b)
	return copy(b, c.reply), nil
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, string(b))
	return len(b), nil
}

type countedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestStreamPacketWritesOneDatagramPerWrite(t *testing.T) {
	conn := &recordConn{}
	c := StreamPacket(conn, streamPeer)
	pc, ok := c.(net.PacketConn)
	if !ok {
		t.Fatal("StreamPacket result is not a net.PacketConn")
	}
	if n, err := c.Write([]byte("one")); n != 3 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	same := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	if n, err := pc.WriteTo([]byte("two"), same); n != 3 || err != nil {
		t.Fatalf("WriteTo(%v) = %d, %v", same, n, err)
	}
	for _, addr := range []net.Addr{NewNetAddr("udp", "192.0.2.2:53"), nil} {
		if n, err := pc.WriteTo([]byte("three"), addr); n != 0 || err == nil {
			t.Fatalf("WriteTo(%v) = %d, %v, want an error", addr, n, err)
		}
	}
	if want := []string{"one", "two"}; !slices.Equal(conn.writes, want) {
		t.Fatalf("conn got writes %q, want %q", conn.writes, want)
	}
}

func TestStreamPacketReadsOneChunkPerRead(t *testing.T) {
	conn := &recordConn{reply: "chunk"}
	c := StreamPacket(conn, streamPeer)
	b := make([]byte, 64)
	if n, err := c.Read(b); err != nil || string(b[:n]) != "chunk" {
		t.Fatalf("Read = %q, %v", b[:n], err)
	}
	n, from, err := c.(net.PacketConn).ReadFrom(b)
	if err != nil || string(b[:n]) != "chunk" || from != streamPeer {
		t.Fatalf("ReadFrom = %q from %v, %v; want \"chunk\" from %v", b[:n], from, err, streamPeer)
	}
	if len(conn.reads) != 2 {
		t.Fatalf("conn got %d reads, want 2", len(conn.reads))
	}
	for _, got := range conn.reads {
		if len(got) != len(b) || &got[0] != &b[0] {
			t.Fatal("conn read into another buffer than the caller's")
		}
	}
}

func TestStreamPacketAddresses(t *testing.T) {
	local, _ := net.Pipe()
	c := StreamPacket(local, streamPeer)
	if c.RemoteAddr() != streamPeer || c.LocalAddr() != local.LocalAddr() {
		t.Fatalf("addresses %v -> %v, want %v -> %v", c.LocalAddr(), c.RemoteAddr(), local.LocalAddr(), streamPeer)
	}
}

func TestStreamPacketForwardsDeadlines(t *testing.T) {
	local, _ := net.Pipe()
	c := StreamPacket(local, streamPeer)
	past := time.Now().Add(-time.Second)
	buf := make([]byte, 8)
	for name, set := range map[string]func(time.Time) error{"SetDeadline": c.SetDeadline, "SetReadDeadline": c.SetReadDeadline} {
		if err := set(past); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read after %s(past) = %v, want a deadline error", name, err)
		}
		c.SetDeadline(time.Time{})
	}
	for name, set := range map[string]func(time.Time) error{"SetDeadline": c.SetDeadline, "SetWriteDeadline": c.SetWriteDeadline} {
		if err := set(past); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write after %s(past) = %v, want a deadline error", name, err)
		}
		c.SetDeadline(time.Time{})
	}
}

func TestStreamPacketKeepsConnErrors(t *testing.T) {
	local, remote := net.Pipe()
	c := StreamPacket(local, streamPeer)
	pc := c.(net.PacketConn)
	remote.Close()
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err != io.EOF {
		t.Fatalf("Read = %v, want io.EOF unchanged", err)
	}
	if _, _, err := pc.ReadFrom(buf); err != io.EOF {
		t.Fatalf("ReadFrom = %v, want io.EOF unchanged", err)
	}
	if _, err := c.Write(buf); err != io.ErrClosedPipe {
		t.Fatalf("Write = %v, want io.ErrClosedPipe unchanged", err)
	}
	if _, err := pc.WriteTo(buf, streamPeer); err != io.ErrClosedPipe {
		t.Fatalf("WriteTo = %v, want io.ErrClosedPipe unchanged", err)
	}
}

func TestStreamPacketClosesConnOnce(t *testing.T) {
	local, _ := net.Pipe()
	conn := &countedConn{Conn: local}
	c := StreamPacket(conn, streamPeer)
	for range 2 {
		if err := c.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
	}
	if n := conn.closes.Load(); n != 1 {
		t.Fatalf("conn closed %d times, want once", n)
	}
}
