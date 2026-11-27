package quic_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	xquic "golang.org/x/net/quic"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// sniListen listens with x/net/quic itself on a certificate for dnsName, reporting the name each ClientHello asks for.
func sniListen(t *testing.T, dnsName string) (addr, caFile string, names <-chan string) {
	t.Helper()
	caFile, certFile, keyFile := testutils.Issue(t, dnsName)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 8)
	ep, err := xquic.Listen("udp", "127.0.0.1:0", &xquic.Config{TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"permuteproxy"},
		MinVersion:   tls.VersionTLS13,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			seen <- hello.ServerName
			return nil, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ep.Close(ctx)
		ep.Close(context.Background())
	})
	go func() {
		for {
			qc, err := ep.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := qc.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						io.Copy(s, s)
						s.Close()
					}()
				}
			}()
		}
	}()
	return ep.LocalAddr().String(), caFile, seen
}

// The names a quic dial resolves go to the system resolver, so the endpoint host here is localhost.
func TestServerNameDefaultsToTheEndpointHost(t *testing.T) {
	tests := []struct {
		name    string
		cert    string // the name the server's certificate is for
		ip      bool   // the endpoint is written as an ip
		opts    permuteproxy.Options
		verify  bool // the dialer verifies against the server's CA
		sni     string
		refused bool // the handshake fails
	}{
		{name: "endpoint host", cert: "localhost", verify: true, sni: "localhost"},
		{name: "explicit name wins", cert: "proxy.test", opts: permuteproxy.Options{"tls_server_name": "proxy.test"}, verify: true, sni: "proxy.test"},
		{name: "explicit name is verified", cert: "localhost", opts: permuteproxy.Options{"tls_server_name": "other.test"}, verify: true, sni: "other.test", refused: true},
		{name: "host the certificate lacks", cert: "proxy.test", verify: true, sni: "localhost", refused: true},
		{name: "skipping verification still names the host", cert: "proxy.test", opts: permuteproxy.Options{"tls_skip_verify": "true"}, sni: "localhost"},
		{name: "skipping verification keeps an explicit name", cert: "proxy.test", opts: permuteproxy.Options{"tls_skip_verify": "true", "tls_server_name": "other.test"}, sni: "other.test"},
		{name: "ip is verified and not sent", cert: "localhost", ip: true, verify: true, sni: "", refused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, caFile, names := sniListen(t, tt.cert)
			_, port, _ := net.SplitHostPort(addr)
			opts := permuteproxy.Options{}
			for k, v := range tt.opts {
				opts[k] = v
			}
			if tt.verify {
				opts["tls_ca_file"] = caFile
			}
			if !tt.ip {
				addr = "localhost:" + port
			}
			tr := build(t, permuteproxy.TransportEngine{}, quicChain(addr, opts))
			t.Cleanup(func() { tr.(io.Closer).Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := tr.Dial(ctx, permuteproxy.Stream)
			if err == nil {
				defer conn.Close()
			}
			if tt.refused != (err != nil) {
				t.Fatalf("Dial = %v, want refused %t", err, tt.refused)
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
