package testutils

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// network is the method set of the module's Network, which this package cannot import.
type network interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

var _ network = (*CountingNetwork)(nil)

func TestCountingNetworkRefusesEveryCall(t *testing.T) {
	n := &CountingNetwork{}
	ctx := context.Background()
	if conn, err := n.DialContext(ctx, "tcp", "127.0.0.1:1"); conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext = %v, %v; want net.ErrClosed", conn, err)
	}
	if ln, err := n.Listen(ctx, "tcp", "127.0.0.1:0"); ln != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Listen = %v, %v; want net.ErrClosed", ln, err)
	}
	if pc, err := n.ListenPacket(ctx, "udp", "127.0.0.1:0"); pc != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ListenPacket = %v, %v; want net.ErrClosed", pc, err)
	}
}

func TestCountingNetworkCountsEveryCall(t *testing.T) {
	n := &CountingNetwork{}
	ctx := context.Background()
	n.DialContext(ctx, "tcp", "127.0.0.1:1")
	n.Listen(ctx, "tcp", "127.0.0.1:0")
	n.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if got := n.Calls.Load(); got != 3 {
		t.Fatalf("Calls = %d after one call of each method, want 3", got)
	}
}

func TestCountingConnCountsEachClose(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	var closes atomic.Int32
	c := CountingConn{Conn: conn, Closes: &closes}
	c.Close()
	c.Close()
	if got := closes.Load(); got != 2 {
		t.Fatalf("Closes = %d after two Close calls, want 2", got)
	}
}

func TestCountingConnClosesItsConn(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	CountingConn{Conn: conn, Closes: new(atomic.Int32)}.Close()
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write after Close = %v, want the conn closed", err)
	}
}
