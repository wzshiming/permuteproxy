package tls_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// rerouted dials addr whatever address it is asked for, as a resolver knowing every name would.
type rerouted struct {
	permuteproxy.Network
	addr net.Addr
}

func (r rerouted) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return r.Network.DialContext(ctx, r.addr.Network(), r.addr.String())
}

// sniServer serves tls on network at address with a certificate for proxy.test, reporting the name each ClientHello asks for.
func sniServer(t *testing.T, network, address string) (addr net.Addr, caFile string, names <-chan string) {
	t.Helper()
	caFile, certFile, keyFile := testutils.Issue(t, "proxy.test")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 8)
	ln, err := tls.Listen(network, address, &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			seen <- hello.ServerName
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return testutils.ServeEcho(t, ln), caFile, seen
}

func TestServerNameDefaultsToTheEndpointHost(t *testing.T) {
	addr, caFile, names := sniServer(t, "tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(addr.String())
	ca := "tls_ca_file=" + caFile
	tests := []struct {
		name     string
		uri      string
		sni      string
		verified bool // the handshake succeeds with a verified chain
		refused  bool // the handshake fails on the certificate
	}{
		{name: "endpoint host", uri: "tls://proxy.test:" + port + "?" + ca, sni: "proxy.test", verified: true},
		{name: "explicit name wins", uri: "tls://other.test:" + port + "?tls_server_name=proxy.test&" + ca, sni: "proxy.test", verified: true},
		{name: "explicit name is verified", uri: "tls://proxy.test:" + port + "?tls_server_name=other.test&" + ca, sni: "other.test", refused: true},
		{name: "host the certificate lacks", uri: "tls://other.test:" + port + "?" + ca, sni: "other.test", refused: true},
		{name: "skipping verification still names the host", uri: "tls://other.test:" + port + "?tls_skip_verify=true", sni: "other.test"},
		{name: "skipping verification keeps an explicit name", uri: "tls://proxy.test:" + port + "?tls_skip_verify=true&tls_server_name=other.test", sni: "other.test"},
		{name: "ip is verified and not sent", uri: "tls://" + addr.String() + "?" + ca, sni: "", refused: true},
		{name: "ip is not sent", uri: "tls://" + addr.String() + "?tls_skip_verify=true", sni: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := transport(t, permuteproxy.TransportEngine{Base: rerouted{testutils.System{}, addr}}, tt.uri)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := tr.Dial(ctx, permuteproxy.Stream)
			if err == nil {
				defer conn.Close()
			}
			var certErr *tls.CertificateVerificationError
			switch {
			case tt.refused && !errors.As(err, &certErr):
				t.Fatalf("Dial = %v, want a certificate verification error", err)
			case !tt.refused && err != nil:
				t.Fatal(err)
			case tt.verified && len(conn.(*tls.Conn).ConnectionState().VerifiedChains) == 0:
				t.Fatal("handshake succeeded without a verified chain")
			}
			select {
			case got := <-names:
				if got != tt.sni {
					t.Fatalf("server saw SNI %q, want %q", got, tt.sni)
				}
			case <-ctx.Done():
				t.Fatal("server saw no ClientHello")
			}
		})
	}
}

func TestServerNameHasNoDefaultOffHostPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.test")
	addr, caFile, names := sniServer(t, "unix", path)
	chain := func(opts permuteproxy.Options) permuteproxy.Chain {
		return permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "tls", Options: opts}}, Endpoint: permuteproxy.Endpoint{Network: "unix", Address: addr.String()}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr, err := permuteproxy.TransportEngine{}.Transport(chain(permuteproxy.Options{"tls_ca_file": caFile}))
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := tr.Dial(ctx, permuteproxy.Stream); err == nil {
		conn.Close()
		t.Fatal("handshake without a server name succeeded")
	}
	select {
	case got := <-names:
		t.Fatalf("server saw a ClientHello asking for %q, want none sent", got)
	default:
	}

	tr, err = permuteproxy.TransportEngine{}.Transport(chain(permuteproxy.Options{"tls_skip_verify": "true"}))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := <-names; got != "" {
		t.Fatalf("server saw SNI %q, want none", got)
	}
}
