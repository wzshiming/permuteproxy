package socks4

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/socks4"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

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
				base := &testutils.CountingNetwork{}
				c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: scheme}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:1"}}
				n, err := permuteproxy.Engine{Base: base}.Client(c)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := n.DialContext(context.Background(), network, address); !errors.Is(err, permuteproxy.ErrUnsupported) {
					t.Fatalf("DialContext(%s) = %v, want ErrUnsupported", network, err)
				}
				if got := base.Calls.Load(); got != 0 {
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

func wait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: timed out", what)
	}
	panic("unreachable")
}

// freeAddress is a loopback tcp address nothing listens on.
func freeAddress(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	ln.Close()
	return ln.Addr().String()
}

type accepted struct {
	conn net.Conn
	err  error
}

func TestASecondRunBindsTheAddressTheFirstBound(t *testing.T) {
	target := freeAddress(t)
	proxies := make(chan string, 1)
	base := permuteproxy.NetworkFuncs{ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err == nil {
			proxies <- ln.Addr().String()
		}
		return ln, err
	}}
	binds := make(chan error, 1)
	upstream := permuteproxy.NetworkFuncs{ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		binds <- err
		return ln, err
	}}
	c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "socks4"}}, Endpoint: permuteproxy.Endpoint{Network: "tcp", Address: "127.0.0.1:0"}}
	srv, err := permuteproxy.Engine{Base: base, Upstream: upstream}.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	for run := 1; run <= 2; run++ {
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.Run(ctx) }()
		dialer := &socks4.Dialer{ProxyNetwork: "tcp", ProxyAddress: wait(t, proxies, "the proxy's listener")}
		bind, err := dialer.Listen(ctx, "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		replies := make(chan accepted, 1)
		go func() {
			conn, err := bind.Accept()
			replies <- accepted{conn, err}
		}()
		if err := wait(t, binds, "the BIND listen"); err != nil {
			t.Fatalf("run %d: BIND listen on %s = %v", run, target, err)
		}
		peer, err := net.Dial("tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		reply := wait(t, replies, "the BIND reply")
		if reply.err != nil {
			t.Fatalf("run %d: BIND = %v", run, reply.err)
		}
		if got, want := reply.conn.RemoteAddr().String(), peer.LocalAddr().String(); got != want {
			t.Fatalf("run %d: BIND accepted %s, want %s", run, got, want)
		}
		reply.conn.Close()
		peer.Close()
		stop()
		if err := wait(t, done, "Run"); err != nil {
			t.Fatalf("run %d: Run = %v", run, err)
		}
	}
}

// notifyingListener closes closed on its first Close.
type notifyingListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *notifyingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func TestABindListenerOpenedAfterServeReturnedIsClosed(t *testing.T) {
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := permuteproxy.NetworkFuncs{ListenFunc: func(_ context.Context, network, address string) (net.Listener, error) {
		close(entered)
		<-release
		ln, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { ln.Close() })
		return &notifyingListener{Listener: ln, closed: closed}, nil
	}}
	funcs, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(context.Background(), ln, upstream) }()
	bind, err := (&socks4.Dialer{ProxyNetwork: "tcp", ProxyAddress: ln.Addr().String()}).Listen(context.Background(), "tcp", freeAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	go bind.Accept()
	wait(t, entered, "the BIND listen")
	ln.Close()
	wait(t, done, "Serve")
	close(release)
	wait(t, closed, "the close of a BIND listener opened after Serve returned")
}

func TestABindTheUpstreamCannotListenForIsRefused(t *testing.T) {
	upstream := permuteproxy.NetworkFuncs{ListenFunc: func(context.Context, string, string) (net.Listener, error) {
		return nil, errors.New("no listener")
	}}
	funcs, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(context.Background(), ln, upstream) }()
	bind, err := (&socks4.Dialer{ProxyNetwork: "tcp", ProxyAddress: ln.Addr().String()}).Listen(context.Background(), "tcp", freeAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	replies := make(chan accepted, 1)
	go func() {
		conn, err := bind.Accept()
		replies <- accepted{conn, err}
	}()
	if reply := wait(t, replies, "the BIND reply"); reply.err == nil {
		reply.conn.Close()
		t.Fatal("BIND succeeded without a listener")
	}
	ln.Close()
	wait(t, done, "Serve")
}
