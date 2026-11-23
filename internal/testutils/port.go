package testutils

import (
	"net"
	"testing"
)

// ReservePort returns a 127.0.0.1 address whose port was free for tcp and udp alike.
func ReservePort(t testing.TB) string {
	t.Helper()
	for range 100 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		pc, err := net.ListenPacket("udp", addr)
		ln.Close()
		if err == nil {
			pc.Close()
			return addr
		}
	}
	t.Fatal("no 127.0.0.1 port was free for both tcp and udp in 100 tries")
	return ""
}
