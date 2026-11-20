package socks4

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

func TestURIKeepsNamesAndKeys(t *testing.T) {
	for _, scheme := range []string{"socks4", "socks4a"} {
		t.Run(scheme, func(t *testing.T) {
			uri := scheme + "://u:p@127.0.0.1:1"
			c, err := permuteproxy.ParseURI(uri)
			if err != nil {
				t.Fatal(err)
			}
			want := []permuteproxy.Layer{{Scheme: scheme, Options: permuteproxy.Options{"username": "u", "password": "p"}}}
			if !reflect.DeepEqual(c.Layers, want) {
				t.Fatalf("ParseURI(%q).Layers = %+v, want %+v", uri, c.Layers, want)
			}
			if back, err := c.URI(); back != uri || err != nil {
				t.Fatalf("URI() = %q, %v, want %q", back, err, uri)
			}
			if _, err := permuteproxy.ParseURI(scheme + "://127.0.0.1:1?bogus=1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
				t.Fatalf("ParseURI with an undeclared option = %v, want ErrInvalidChain", err)
			}
		})
	}
}

func TestClientRefusesUDPAndUnix(t *testing.T) {
	for _, scheme := range []string{"socks4", "socks4a"} {
		for network, address := range map[string]string{"udp": "127.0.0.1:1", "unix": "./test.sock"} {
			t.Run(scheme+"/"+network, func(t *testing.T) {
				base := &countingNetwork{}
				c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: scheme}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:1"}}
				n, err := permuteproxy.Engine{Base: base}.Client(c)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := n.DialContext(context.Background(), network, address); !errors.Is(err, permuteproxy.ErrUnsupported) {
					t.Fatalf("DialContext(%s) = %v, want ErrUnsupported", network, err)
				}
				if got := base.calls.Load(); got != 0 {
					t.Fatalf("base calls = %d, want 0", got)
				}
			})
		}
	}
}
