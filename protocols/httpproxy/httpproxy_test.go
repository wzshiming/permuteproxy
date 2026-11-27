package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/wzshiming/httpproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestURIKeepsNameAndKeys(t *testing.T) {
	uri := "http://u:p@127.0.0.1:1"
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	want := []permuteproxy.Layer{{Scheme: "http", Options: permuteproxy.Options{"username": "u", "password": "p"}}}
	if !reflect.DeepEqual(c.Layers, want) {
		t.Fatalf("ParseURI(%q).Layers = %+v, want %+v", uri, c.Layers, want)
	}
	if back, err := c.URI(); back != uri || err != nil {
		t.Fatalf("URI() = %q, %v, want %q", back, err, uri)
	}
	if _, err := permuteproxy.ParseURI("http://127.0.0.1:1?bogus=1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Fatalf("ParseURI with an undeclared option = %v, want ErrInvalidChain", err)
	}
}

func TestClientRefusesUDPAndUnix(t *testing.T) {
	for network, address := range map[string]string{"udp": "127.0.0.1:1", "unix": "./test.sock"} {
		t.Run(network, func(t *testing.T) {
			base := &testutils.CountingNetwork{}
			c := permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "http"}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:1"}}
			n, err := permuteproxy.ClientEngine{Base: base}.Client(c)
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

func TestClientSendsCONNECTOverInner(t *testing.T) {
	funcs, err := NewClient(permuteproxy.Options{"username": "u", "password": "p"})
	if err != nil {
		t.Fatal(err)
	}
	carrier, proxy := net.Pipe()
	defer proxy.Close()
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(context.Context, permuteproxy.Plane) (net.Conn, error) {
		return carrier, nil
	}}
	requests := make(chan *http.Request, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(proxy))
		if err != nil {
			return
		}
		requests <- req
		io.WriteString(proxy, "HTTP/1.1 200 OK\r\n\r\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := funcs.Dial(ctx, inner, "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	req := <-requests
	// dTpw is u:p in base64.
	if req.Method != http.MethodConnect || req.Host != "example.com:80" || req.Header.Get("Proxy-Authorization") != "Basic dTpw" {
		t.Fatalf("request = %s %s %q, want CONNECT example.com:80 \"Basic dTpw\"", req.Method, req.Host, req.Header.Get("Proxy-Authorization"))
	}
}

func TestServerReachesTargetThroughUpstream(t *testing.T) {
	funcs, err := NewServer(permuteproxy.Options{"username": "u", "password": "p"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dials := make(chan string, 1)
	upstream := permuteproxy.NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
		dials <- network + " " + address
		target, _ := net.Pipe()
		return target, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- funcs.Serve(ctx, ln, upstream) }()
	defer func() { ln.Close(); <-done }()
	dialer := &httpproxy.Dialer{Proxy: ln.Addr().String(), Userinfo: url.UserPassword("u", "p")}
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got, want := <-dials, "tcp example.com:80"; got != want {
		t.Fatalf("upstream dial = %q, want %q", got, want)
	}
}
