package testutils

import (
	"context"
	"testing"
	"time"
)

var _ network = System{}

func TestSystemDialsWhatItListensOn(t *testing.T) {
	ctx := context.Background()
	ln, err := System{}.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := System{}.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if got, want := peer.RemoteAddr().String(), conn.LocalAddr().String(); got != want {
		t.Fatalf("accepted a conn from %s, want the one dialed from %s", got, want)
	}
}

func TestSystemListensPacket(t *testing.T) {
	pc, err := System{}.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo([]byte("self"), pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, from, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "self" || from.String() != pc.LocalAddr().String() {
		t.Fatalf("ReadFrom = %q from %v, %v; want the datagram the socket sent itself", buf[:n], from, err)
	}
}
