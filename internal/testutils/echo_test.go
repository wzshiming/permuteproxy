package testutils

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestServeEchoEchoesEachConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ServeEcho(t, ln)
	for range 2 {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
			t.Fatalf("read %q, %v; want ping echoed", got, err)
		}
	}
}

func TestServeEchoClosesTheListenerWhenTheTestEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Run("serve", func(t *testing.T) { ServeEcho(t, ln) })
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after the test ended = %v, want net.ErrClosed", err)
	}
}

func TestServePacketEchoAnswersEachSender(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ServePacketEcho(t, pc)
	for _, msg := range []string{"one", "two"} {
		conn, err := net.Dial("udp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		if n, err := conn.Read(buf); err != nil || string(buf[:n]) != msg {
			t.Fatalf("read %q, %v; want %q echoed", buf[:n], err, msg)
		}
	}
}

func TestServePacketEchoClosesTheSocketWhenTheTestEnds(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	t.Run("serve", func(t *testing.T) { ServePacketEcho(t, pc) })
	pc.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after the test ended = %v, want net.ErrClosed", err)
	}
}

func TestUDPEchoAnswersOnLoopback(t *testing.T) {
	addr := UDPEcho(t)
	if udp, ok := addr.(*net.UDPAddr); !ok || !udp.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("UDPEcho = %v, want a udp address on 127.0.0.1", addr)
	}
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("read %q, %v; want ping echoed", buf[:n], err)
	}
}
