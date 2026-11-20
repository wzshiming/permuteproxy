package socks4

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/socks4"

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

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestClientSpeaksSOCKS4OverInner(t *testing.T) {
	// CONNECT to 127.0.0.1:80 as user u.
	const request = "\x04\x01\x00\x50\x7f\x00\x00\x01u\x00"
	funcs, err := NewClient(permuteproxy.Options{"username": "u"})
	if err != nil {
		t.Fatal(err)
	}
	carrier, proxy := net.Pipe()
	defer proxy.Close()
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(context.Context, permuteproxy.Plane) (net.Conn, error) {
		return carrier, nil
	}}
	requests := make(chan string, 1)
	go func() {
		req := make([]byte, len(request))
		if _, err := io.ReadFull(proxy, req); err != nil {
			return
		}
		requests <- string(req)
		proxy.Write([]byte("\x00\x5a\x00\x00\x00\x00\x00\x00"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := funcs.Dial(ctx, inner, "tcp", "127.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := <-requests; got != request {
		t.Fatalf("request = %q, want %q", got, request)
	}
}

func TestServerReachesTargetThroughUpstream(t *testing.T) {
	funcs, err := NewServer(permuteproxy.Options{"username": "u"})
	if err != nil {
		t.Fatal(err)
	}
	target, ln := listen(t), listen(t)
	dials := make(chan string, 1)
	upstream := permuteproxy.NetworkFuncs{DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		dials <- network + " " + address
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(ctx, ln, upstream) }()
	defer func() { ln.Close(); <-done }()
	dialer := &socks4.Dialer{ProxyNetwork: "tcp", ProxyAddress: ln.Addr().String(), Username: "u"}
	conn, err := dialer.DialContext(ctx, "tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got, want := <-dials, "tcp "+target.Addr().String(); got != want {
		t.Fatalf("upstream dial = %q, want %q", got, want)
	}
}
