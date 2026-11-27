package all_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// tlsBase serves tls on each listener with a certificate, reporting the name each ClientHello asks for.
type tlsBase struct {
	permuteproxy.Network
	cert  tls.Certificate
	bound chan net.Addr
	names chan string
}

func (b tlsBase) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	ln, err := b.Network.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	b.bound <- ln.Addr()
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{b.cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			b.names <- hello.ServerName
			return nil, nil
		},
	}), nil
}

// rerouted dials addr whatever address it is asked for, as a resolver knowing every name would.
type rerouted struct {
	permuteproxy.Network
	addr net.Addr
}

func (r rerouted) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return r.Network.DialContext(ctx, r.addr.Network(), r.addr.String())
}

func TestProxyOverTLSNamesTheEndpointHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("OK"))
	}))
	t.Cleanup(target.Close)
	caFile, certFile, keyFile := testutils.Issue(t, "proxy.test")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		host    string
		query   string
		sni     string
		refused bool
	}{
		{name: "endpoint host", host: "proxy.test", sni: "proxy.test"},
		{name: "explicit name", host: "other.test", query: "&tls_server_name=proxy.test", sni: "proxy.test"},
		{name: "explicit name the certificate lacks", host: "proxy.test", query: "&tls_server_name=other.test", sni: "other.test", refused: true},
		{name: "host the certificate lacks", host: "other.test", sni: "other.test", refused: true},
	}
	// The server speaks the proxy protocol alone; its base wraps the listener in tls to see the ClientHello.
	for client, server := range map[string]string{"https": "http", "socks5+tls": "socks5"} {
		for _, tt := range tests {
			t.Run(client+"/"+tt.name, func(t *testing.T) {
				base := tlsBase{Network: testutils.System{}, cert: cert, bound: make(chan net.Addr, 1), names: make(chan string, 8)}
				_, done := start(t, permuteproxy.ServerEngine{Base: base}, parse(t, server+"://127.0.0.1:0"))
				var addr net.Addr
				select {
				case addr = <-base.bound:
				case err := <-done:
					t.Fatalf("server exited before binding: %v", err)
				}
				_, port, _ := net.SplitHostPort(addr.String())
				n, err := permuteproxy.ClientEngine{Base: rerouted{testutils.System{}, addr}}.Client(parse(t, client+"://"+tt.host+":"+port+"?tls_ca_file="+caFile+tt.query))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { closeIf(n) })
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				body, err := fetch(ctx, n, target.URL)
				switch {
				case tt.refused && err == nil:
					t.Fatal("request succeeded through a proxy whose certificate is for another name")
				case !tt.refused && (err != nil || body != "OK"):
					t.Fatalf("fetch = %q, %v", body, err)
				}
				select {
				case got := <-base.names:
					if got != tt.sni {
						t.Fatalf("server saw SNI %q, want %q", got, tt.sni)
					}
				case <-ctx.Done():
					t.Fatal("server saw no ClientHello")
				}
			})
		}
	}
}
