package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wzshiming/permuteproxy"
)

// hostKeyPEM is the host key of the servers under test, so that none generates an RSA key.
var hostKeyPEM = func() []byte {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(block)
}()

// hostKey is hostKeyPEM as the hostkey_data option carries it.
var hostKey = base64.URLEncoding.EncodeToString(hostKeyPEM)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// echoTarget accepts tcp conns and echoes what each sends.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// recv waits for a value from ch, failing the test after a while.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

// roundTrip writes msg to conn and expects want back; ssh conns refuse deadlines, so the read runs aside.
func roundTrip(t *testing.T, conn net.Conn, msg, want string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	got := make([]byte, len(want))
	go func() {
		_, err := io.ReadFull(conn, got)
		read <- err
	}()
	if err := recv(t, read, "the reply to "+msg); err != nil || string(got) != want {
		t.Fatalf("read %q, %v; want %q", got, err, want)
	}
}

// countingNetwork fails every call a chain makes on it and counts them.
type countingNetwork struct{ calls atomic.Int32 }

func (n *countingNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	n.calls.Add(1)
	return nil, net.ErrClosed
}

func (n *countingNetwork) Listen(context.Context, string, string) (net.Listener, error) {
	n.calls.Add(1)
	return nil, net.ErrClosed
}

func (n *countingNetwork) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	n.calls.Add(1)
	return nil, net.ErrClosed
}

func TestURIKeepsNameAndKeys(t *testing.T) {
	uri := "ssh://u:p@127.0.0.1:1?authorized_data=a&authorized_file=b&hostkey_data=c&hostkey_file=d&identity_data=e&identity_file=f"
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	want := []permuteproxy.Layer{{Scheme: "ssh", Options: permuteproxy.Options{
		"username": "u", "password": "p",
		"authorized_data": "a", "authorized_file": "b", "hostkey_data": "c", "hostkey_file": "d", "identity_data": "e", "identity_file": "f",
	}}}
	if !reflect.DeepEqual(c.Layers, want) {
		t.Fatalf("ParseURI(%q).Layers = %+v, want %+v", uri, c.Layers, want)
	}
	if back, err := c.URI(); back != uri || err != nil {
		t.Fatalf("URI() = %q, %v, want %q", back, err, uri)
	}
	if _, err := permuteproxy.ParseURI("ssh://127.0.0.1:1?bogus=1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Fatalf("ParseURI with an undeclared option = %v, want ErrInvalidChain", err)
	}
}

func TestClientRefusesUnixgramAndListen(t *testing.T) {
	ctx := context.Background()
	base := &countingNetwork{}
	n, err := permuteproxy.Engine{Base: base}.Client(permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "ssh"}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DialContext(ctx, "unixgram", "./test.sock"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(unixgram) = %v, want ErrUnsupported", err)
	}
	for _, network := range []string{"tcp", "unix"} {
		if _, err := n.Listen(ctx, network, "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("Listen(%s) = %v, want ErrUnsupported", network, err)
		}
	}
	if got := base.calls.Load(); got != 0 {
		t.Fatalf("base calls = %d, want 0", got)
	}
}

func TestFuncsTunnelOverInnerToUpstream(t *testing.T) {
	opts := permuteproxy.Options{"username": "u", "password": "p"}
	server, err := NewServer(permuteproxy.Options{"username": "u", "password": "p", "hostkey_data": hostKey})
	if err != nil {
		t.Fatal(err)
	}
	target, ln := echoTarget(t), listen(t)
	dials := make(chan string, 1)
	upstream := permuteproxy.NetworkFuncs{DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		dials <- network + " " + address
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln, upstream) }()
	defer func() {
		ln.Close()
		<-done
	}()
	client, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(ctx context.Context, _ permuteproxy.Plane) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}}
	conn, err := client.Dial(ctx, inner, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "ping")
	if got, want := recv(t, dials, "the upstream dial"), "tcp "+target; got != want {
		t.Fatalf("upstream dial = %q, want %q", got, want)
	}
}

func TestClosedClientRefusesWithoutReconnecting(t *testing.T) {
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
	ctx, target := timeout(t), echoTarget(t)
	conn, err := n.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := n.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ network, address string }{{"tcp", target}, {"cmd", "relay x"}, {"udp", "198.51.100.7:53"}} {
		if conn, err := n.DialContext(ctx, d.network, d.address); !errors.Is(err, net.ErrClosed) {
			if conn != nil {
				conn.Close()
			}
			t.Errorf("dial %s after Close = %v, want net.ErrClosed", d.network, err)
		}
	}
	if got := base.dials.Load(); got != 1 {
		t.Fatalf("client dials = %d, want only the first: no reconnect after Close", got)
	}
}
