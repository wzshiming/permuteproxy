package quic_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
	_ "github.com/wzshiming/permuteproxy/protocols/quic"
	_ "github.com/wzshiming/permuteproxy/protocols/socks5"
)

func TestQUICProvidesStreamOverUDP(t *testing.T) {
	for _, uri := range []string{"quic://127.0.0.1:1", "socks5+quic://127.0.0.1:1"} {
		c, err := permuteproxy.ParseURI(uri)
		if err == nil {
			err = c.Validate()
		}
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
	}
	c, err := permuteproxy.ParseURI("quic://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := permuteproxy.TransportEngine{}.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Planes() != permuteproxy.Stream {
		t.Fatalf("Planes() = %v, want stream", tr.Planes())
	}
}

func TestQUICRequiresDatagramsWithBoundaries(t *testing.T) {
	for uri, valid := range map[string]bool{
		"quic+udp://127.0.0.1:1":       true,
		"quic+tcp://127.0.0.1:1":       false,
		"quic+dgram+tcp://127.0.0.1:1": false,
	} {
		c, err := permuteproxy.ParseURI(uri)
		if err == nil {
			err = c.Validate()
		}
		if valid && err != nil || !valid && !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("%s: %v, want valid %v", uri, err, valid)
		}
	}
}

func TestQUICAcceptsTheTLSOptionsButACME(t *testing.T) {
	for _, key := range tlsutils.OptionKeysWithoutACME() {
		if _, err := permuteproxy.ParseURI("quic://127.0.0.1:1?" + key + "="); err != nil {
			t.Errorf("quic URI with %s: %v", key, err)
		}
	}
	for _, key := range []string{"tls_acme_host", "tls_acme_cache_dir"} {
		if _, err := permuteproxy.ParseURI("quic://127.0.0.1:1?" + key + "=x"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("quic URI with %s: %v, want ErrInvalidChain", key, err)
		}
	}
}

// recorder is a base network that notes the network of each bind and fails it.
type recorder struct {
	permuteproxy.NetworkFuncs
	networks chan string
}

func newRecorder() *recorder {
	return &recorder{networks: make(chan string, 8)}
}

func (r *recorder) ListenPacket(_ context.Context, network, _ string) (net.PacketConn, error) {
	r.networks <- network
	return nil, errors.New("recorded")
}

func TestSOCKS5OverQUICBindsAUDPCarrier(t *testing.T) {
	base := newRecorder()
	c, err := permuteproxy.ParseURI("socks5+quic://127.0.0.1:1?tls_skip_verify=true")
	if err != nil {
		t.Fatal(err)
	}
	n, err := permuteproxy.ClientEngine{Base: base}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DialContext(context.Background(), "tcp", "127.0.0.1:2"); err == nil {
		t.Fatal("dial over a carrier that failed to bind succeeded")
	}
	select {
	case network := <-base.networks:
		if network != "udp" {
			t.Fatalf("carrier bound on %q, want udp", network)
		}
	default:
		t.Fatal("no carrier was bound")
	}
}
