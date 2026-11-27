package socks4

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// client is a socks4 client, as user u, of a server it runs on loopback over upstream.
func client(t *testing.T, upstream permuteproxy.Network) permuteproxy.Network {
	t.Helper()
	opts := permuteproxy.Options{"username": "u"}
	funcs, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(ctx, ln, upstream) }()
	t.Cleanup(func() { cancel(); ln.Close(); <-done })
	c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "socks4", Options: opts}}, Endpoint: permuteproxy.Endpoint{Address: ln.Addr().String()}}
	n, err := permuteproxy.ClientEngine{Base: testutils.System{}}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestClientSpeaksBINDOverInner(t *testing.T) {
	// BIND 0.0.0.0:80 as user u.
	const request = "\x04\x02\x00\x50\x00\x00\x00\x00u\x00"
	funcs, err := NewClient(permuteproxy.Options{"username": "u"})
	if err != nil {
		t.Fatal(err)
	}
	carrier, proxy := net.Pipe()
	defer proxy.Close()
	dials := 0
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(context.Context, permuteproxy.Plane) (net.Conn, error) {
		if dials++; dials > 1 {
			return nil, errors.New("only one request is answered")
		}
		return carrier, nil
	}}
	requests := make(chan string, 1)
	go func() {
		req := make([]byte, len(request))
		if _, err := io.ReadFull(proxy, req); err != nil {
			return
		}
		requests <- string(req)
		// Bound at 10.0.0.1:80, then accepted 10.0.0.2:4660.
		proxy.Write([]byte("\x00\x5a\x00\x50\x0a\x00\x00\x01"))
		proxy.Write([]byte("\x00\x5a\x12\x34\x0a\x00\x00\x02"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := funcs.Listen(ctx, inner, "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := <-requests; got != request {
		t.Fatalf("request = %q, want %q", got, request)
	}
	if got := ln.Addr().String(); got != "10.0.0.1:80" {
		t.Fatalf("Addr = %s, want 10.0.0.1:80", got)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != "10.0.0.2:4660" {
		t.Fatalf("RemoteAddr = %s, want 10.0.0.2:4660", got)
	}
}

func TestListenAcceptsAtTheProxy(t *testing.T) {
	n := client(t, testutils.System{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := n.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Each BIND accepts one connection, so later ones show the listener asked again for its address.
	for range 3 {
		peer, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if got, want := conn.RemoteAddr().String(), peer.LocalAddr().String(); got != want {
			t.Fatalf("RemoteAddr = %s, want the peer's %s", got, want)
		}
		go io.Copy(peer, peer)
		testutils.RoundTrip(t, conn, "ping", "ping")
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

func TestListenFailsWhenTheProxyCannotBind(t *testing.T) {
	n := client(t, permuteproxy.NetworkFuncs{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ln, err := n.Listen(ctx, "tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("Listen succeeded at a proxy whose upstream cannot listen")
	}
	if _, err := n.Listen(ctx, "tcp", "[::1]:0"); err == nil {
		t.Fatal("Listen succeeded at an IPv6 address")
	}
}
