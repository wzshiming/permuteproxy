package anyproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
)

// pipeListener serves in-memory pipes, so each client write reaches the server as one read.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 8), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero}
}

func (l *pipeListener) dial(t *testing.T) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	l.conns <- server
	client.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { client.Close() })
	return client
}

var upstream permuteproxy.Network = permuteproxy.NetworkFuncs{
	DialContextFunc: (&net.Dialer{}).DialContext,
	ListenFunc:      (&net.ListenConfig{}).Listen,
}

func serve(t *testing.T) *pipeListener {
	t.Helper()
	ln := newPipeListener()
	base := permuteproxy.NetworkFuncs{
		ListenFunc: func(context.Context, string, string) (net.Listener, error) { return ln, nil },
	}
	c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "any"}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:0"}}
	srv, err := permuteproxy.Engine{Base: base, Upstream: upstream}.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after Close")
		}
	})
	return ln
}

func writeAll(t *testing.T, conn net.Conn, chunks ...string) {
	t.Helper()
	for _, chunk := range chunks {
		if _, err := conn.Write([]byte(chunk)); err != nil {
			t.Fatalf("write %q: %v", chunk, err)
		}
	}
}

func expect(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestServerAcceptsSplitPrefix(t *testing.T) {
	for _, tt := range []struct {
		name   string
		chunks []string
		want   string
	}{
		{"socks5 version byte alone", []string{"\x05", "\x01\x00"}, "\x05\x00"},
		{"http method split", []string{"CON", "NECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"}, "HTTP/1.1 "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := serve(t).dial(t)
			writeAll(t, client, tt.chunks...)
			expect(t, client, tt.want)
		})
	}
}

func TestServerRefusesUnknownPrefix(t *testing.T) {
	client := serve(t).dial(t)
	writeAll(t, client, "\xff")
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read = %v, want EOF", err)
	}
}

func TestStalledPrefixDoesNotBlockOthers(t *testing.T) {
	ln := serve(t)
	stalled := ln.dial(t)
	writeAll(t, stalled, "\x05")
	client := ln.dial(t)
	writeAll(t, client, "\x05", "\x01\x00")
	expect(t, client, "\x05\x00")
}

func TestURIKeepsNameAndKeys(t *testing.T) {
	uri := "any://u:p@127.0.0.1:1"
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	want := []permuteproxy.Layer{{Scheme: "any", Options: permuteproxy.Options{"username": "u", "password": "p"}}}
	if !reflect.DeepEqual(c.Layers, want) {
		t.Fatalf("ParseURI(%q).Layers = %+v, want %+v", uri, c.Layers, want)
	}
	if back, err := c.URI(); back != uri || err != nil {
		t.Fatalf("URI() = %q, %v, want %q", back, err, uri)
	}
	if _, err := permuteproxy.ParseURI("any://127.0.0.1:1?bogus=1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Fatalf("ParseURI with an undeclared option = %v, want ErrInvalidChain", err)
	}
}

func TestClientIsUnsupported(t *testing.T) {
	c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "any"}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:1"}}
	if _, err := (permuteproxy.Engine{}).Client(c); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Client = %v, want ErrUnsupported", err)
	}
}

func TestServeReachesTargetThroughUpstream(t *testing.T) {
	funcs, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := newPipeListener()
	dials := make(chan string, 1)
	recording := permuteproxy.NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
		dials <- network + " " + address
		return nil, errors.New("unreachable")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(ctx, ln, recording) }()
	defer func() { ln.Close(); <-done }()
	client := ln.dial(t)
	writeAll(t, client, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
	expect(t, client, "HTTP/1.1 ")
	if got, want := <-dials, "tcp 127.0.0.1:1"; got != want {
		t.Fatalf("upstream dial = %q, want %q", got, want)
	}
}
