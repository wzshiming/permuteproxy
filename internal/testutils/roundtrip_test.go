package testutils

import (
	"net"
	"testing"
)

func TestRoundTripPassesWhenOneReadIsWant(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	go func() {
		buf := make([]byte, 16)
		n, _ := peer.Read(buf)
		peer.Write(append([]byte("re:"), buf[:n]...))
	}()
	RoundTrip(t, conn, "ping", "re:ping")
}

func TestRoundTripFailsWhenOneReadIsNotWant(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	go func() {
		peer.Read(make([]byte, 16))
		peer.Write([]byte("re:"))
		peer.Write([]byte("ping"))
	}()
	r := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		RoundTrip(r, conn, "ping", "re:ping")
	}()
	<-done
	if want := `Read = "re:", <nil>; want "re:ping"`; r.msg != want {
		t.Fatalf("RoundTrip failed with %q, want %q", r.msg, want)
	}
}
