package all_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// dialRetry dials through n until the server behind it has bound.
func dialRetry(t *testing.T, n permuteproxy.Network, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		conn, err := n.DialContext(ctx, "tcp", address)
		if err == nil {
			return conn
		}
		select {
		case <-ctx.Done():
			t.Fatalf("dial %s: %v", address, err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestSimple(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echo := testutils.ServeEcho(t, ln).String()

	// Each chain is one the README shows, served and dialed from the same URI.
	for _, chain := range []struct{ scheme, query string }{
		{scheme: "socks5"},
		{scheme: "socks4"},
		{scheme: "http"},
		{scheme: "ssh"},
		{scheme: "https", query: "?tls_self_signed=true&tls_skip_verify=true"},
		{scheme: "socks5+snappy+tls", query: "?tls_self_signed=true&tls_skip_verify=true"},
		{scheme: "http+snappy+quic", query: "?tls_self_signed=true&tls_skip_verify=true"},
	} {
		t.Run(chain.scheme, func(t *testing.T) {
			uri := chain.scheme + "://user:pass@" + testutils.ReservePort(t) + chain.query
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- permuteproxy.ListenAndServe(ctx, uri) }()

			client, err := permuteproxy.NewClient(uri)
			if err != nil {
				t.Fatal(err)
			}
			conn := dialRetry(t, client, echo)
			testutils.RoundTrip(t, conn, "ping", "ping")
			conn.Close()
			closeIf(client)

			cancel()
			if err := testutils.Wait(t, done, "ListenAndServe to return"); err != nil {
				t.Fatalf("ListenAndServe() = %v, want nil once ctx ends", err)
			}
		})
	}
}

func TestSimpleNewServer(t *testing.T) {
	uri := "socks5://" + testutils.ReservePort(t)
	srv, err := permuteproxy.NewServer(uri)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if err := testutils.Wait(t, done, "Run to return"); err != nil {
		t.Fatalf("Run() = %v, want nil after Close", err)
	}
}

func TestSimpleInvalid(t *testing.T) {
	for _, uri := range []string{"", "nosuch://127.0.0.1:1", "tls://127.0.0.1:1"} {
		if _, err := permuteproxy.NewClient(uri); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("NewClient(%q) = %v, want ErrInvalidChain", uri, err)
		}
		if _, err := permuteproxy.NewServer(uri); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("NewServer(%q) = %v, want ErrInvalidChain", uri, err)
		}
		if err := permuteproxy.ListenAndServe(context.Background(), uri); !errors.Is(err, permuteproxy.ErrInvalidChain) {
			t.Errorf("ListenAndServe(%q) = %v, want ErrInvalidChain", uri, err)
		}
	}
}
