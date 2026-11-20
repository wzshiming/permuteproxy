package sshproxy

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/wzshiming/permuteproxy"
)

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
