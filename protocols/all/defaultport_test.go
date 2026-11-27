package all_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/wzshiming/permuteproxy"
)

var errRecorded = errors.New("recorded")

func TestProtocolsDefaultPort(t *testing.T) {
	tests := []struct {
		uri, want string
	}{
		{"http://proxy.test", "proxy.test:80"},
		{"https://proxy.test", "proxy.test:443"},
		{"http+tls://proxy.test", "proxy.test:443"},
		{"socks4://proxy.test", "proxy.test:1080"},
		{"socks4a://proxy.test", "proxy.test:1080"},
		{"socks5://proxy.test", "proxy.test:1080"},
		{"socks5h://proxy.test", "proxy.test:1080"},
		{"socks5+snappy+tls://proxy.test", "proxy.test:1080"},
		{"ssh://proxy.test", "proxy.test:22"},
		{"ssh://[::1]", "[::1]:22"},
		{"ss://aes-256-gcm:pass@proxy.test", "proxy.test:8379"},
		{"shadowsocks://aes-256-gcm:pass@proxy.test", "proxy.test:8379"},
		{"socks5://proxy.test:9", "proxy.test:9"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			chain, err := permuteproxy.ParseURI(tt.uri)
			if err != nil {
				t.Fatal(err)
			}
			var dialed string
			base := permuteproxy.NetworkFuncs{DialContextFunc: func(_ context.Context, _, address string) (net.Conn, error) {
				dialed = address
				return nil, errRecorded
			}}
			client, err := permuteproxy.ClientEngine{Base: base}.Client(chain)
			if err != nil {
				t.Fatal(err)
			}
			if c, ok := client.(io.Closer); ok {
				defer c.Close()
			}
			if _, err := client.DialContext(t.Context(), "tcp", "192.0.2.1:80"); !errors.Is(err, errRecorded) {
				t.Fatalf("dial = %v, want the base's refusal", err)
			}
			if dialed != tt.want {
				t.Fatalf("dialed %q, want %q", dialed, tt.want)
			}
		})
	}
}

func TestServerListensAtTheDefaultPort(t *testing.T) {
	chain, err := permuteproxy.ParseURI("socks5://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var bound string
	base := permuteproxy.NetworkFuncs{ListenFunc: func(_ context.Context, _, address string) (net.Listener, error) {
		bound = address
		return nil, errRecorded
	}}
	server, err := permuteproxy.ServerEngine{Base: base}.Server(chain)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.Run(t.Context()); !errors.Is(err, errRecorded) {
		t.Fatalf("serve = %v, want the base's refusal", err)
	}
	if bound != "127.0.0.1:1080" {
		t.Fatalf("listened at %q, want 127.0.0.1:1080", bound)
	}
}
