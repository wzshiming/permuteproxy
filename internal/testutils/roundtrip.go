package testutils

import (
	"net"
	"testing"
	"time"
)

// RoundTrip writes msg to conn and wants want back in one read.
func RoundTrip(t testing.TB, conn net.Conn, msg, want string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64<<10)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != want {
		t.Fatalf("Read = %q, %v; want %q", buf[:n], err, want)
	}
}
