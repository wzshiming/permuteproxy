package shadowsocks

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/wzshiming/permuteproxy"
)

type countingPacket struct {
	net.PacketConn
	closes *atomic.Int32
}

func (c countingPacket) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

func TestSessionsCloseOwnedSockets(t *testing.T) {
	var closes atomic.Int32
	s := &sessions{listen: func(ctx context.Context, network, address string) (net.PacketConn, error) {
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return countingPacket{pc, &closes}, nil
	}}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := s.ListenPacket(ctx, "udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if closes.Load() != 2 {
		t.Fatalf("Close closed %d sockets, want 2", closes.Load())
	}
	late, err := s.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if !errors.Is(err, net.ErrClosed) || late != nil {
		t.Fatalf("ListenPacket after Close = %v, %v; want net.ErrClosed", late, err)
	}
	if closes.Load() != 3 {
		t.Fatalf("late socket left open: %d closes, want 3", closes.Load())
	}
	s.Close()
	if closes.Load() != 3 {
		t.Fatal("second Close reached the sockets again")
	}
}

func TestClientRefusesPlaneBeforeIO(t *testing.T) {
	var dials atomic.Int32
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(context.Context, permuteproxy.Plane) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dialed")
	}}
	n, err := NewClient(inner, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := n.DialContext(ctx, "udp", "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(udp) over a stream carrier = %v, want ErrUnsupported", err)
	}
	if _, err := n.ListenPacket(ctx, "udp", ":0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("ListenPacket over a stream carrier = %v, want ErrUnsupported", err)
	}
	if _, err := n.DialContext(ctx, "unixgram", "/p"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(unixgram) = %v, want ErrUnsupported", err)
	}
	if dials.Load() != 0 {
		t.Fatalf("carrier dialed %d times for refused planes", dials.Load())
	}
}
