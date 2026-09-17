package cmdutils

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

var testAddr = netutils.NewNetAddr("cmd", "fake")

// pipeDial stands in for a subprocess: the peer end is handed to the test, the dial ctx recorded.
func pipeDial(peers chan<- net.Conn, ctxs chan<- context.Context) Dial {
	return func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		if name != "fake" || len(args) != 2 || args[1] != "b" {
			return nil, errors.New("unexpected command")
		}
		local, peer := net.Pipe()
		peers <- peer
		ctxs <- ctx
		return local, nil
	}
}

func TestListenerAcceptKeepsFirstByte(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		peer := <-peers
		peer.Write([]byte("hello"))
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("read %q", got)
	}
}

func TestListenerCloseWhileWaitingFirstByte(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	ln, err := Listen(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	peer := <-peers
	ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer Read = %v after Close, want EOF", err)
	}
	if ctx := <-ctxs; ctx.Err() == nil {
		t.Fatal("subprocess context not cancelled after Close")
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

func TestDialCloseCancelsCommand(t *testing.T) {
	peers, ctxs := make(chan net.Conn, 1), make(chan context.Context, 1)
	conn, err := DialContext(context.Background(), pipeDial(peers, ctxs), testAddr, testAddr, []string{"fake", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr() != testAddr {
		t.Fatalf("RemoteAddr = %v", conn.RemoteAddr())
	}
	<-peers
	ctx := <-ctxs
	if ctx.Err() != nil {
		t.Fatal("command context cancelled before Close")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("command context still alive after Close")
	}
}
