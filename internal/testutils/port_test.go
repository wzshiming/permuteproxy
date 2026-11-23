package testutils

import (
	"net"
	"testing"
)

func TestReservePortSkipsHeldUDPPorts(t *testing.T) {
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	held := map[string]bool{}
	// Connected to sink, the held sockets keep their ports without taking datagrams meant for other sockets.
	for range 256 {
		conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		held[conn.LocalAddr().String()] = true
	}
	// 256 held of about 16k ephemeral ports meet some 15 of 1000 tcp picks.
	for range 1000 {
		if addr := ReservePort(t); held[addr] {
			t.Fatalf("ReservePort returned %s, whose udp port is held", addr)
		}
	}
}
