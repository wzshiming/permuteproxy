// Package testutils is the scaffolding the tests of this module share, on the standard library only.
package testutils

import (
	"io"
	"net"
	"testing"
)

// ServeEcho echoes back what each conn ln accepts sends, until the test ends and closes ln.
func ServeEcho(t testing.TB, ln net.Listener) net.Addr {
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr()
}

// ServePacketEcho sends each datagram pc reads back to its sender, until the test ends and closes pc.
func ServePacketEcho(t testing.TB, pc net.PacketConn) net.Addr {
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr()
}

// UDPEcho is ServePacketEcho on a udp socket at 127.0.0.1.
func UDPEcho(t testing.TB) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ServePacketEcho(t, pc)
}
