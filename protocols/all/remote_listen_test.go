package all

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// run serves c with e until the test ends and returns the address its base bound.
func run(t *testing.T, e permuteproxy.ServerEngine, c permuteproxy.Chain) string {
	t.Helper()
	bound := make(chan string, 1)
	base := e.Base
	e.Base = permuteproxy.NetworkFuncs{ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := base.Listen(ctx, network, address)
		if err == nil {
			bound <- ln.Addr().String()
		}
		return ln, err
	}}
	srv, err := e.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	t.Cleanup(func() { srv.Close(); <-done })
	select {
	case addr := <-bound:
		return addr
	case err := <-done:
		t.Fatalf("server exited before binding: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not bind")
	}
	return ""
}

// A client is a Network, so a server whose Base it is listens at the remote proxy instead of locally.
func TestAServerListensAtARemoteProxy(t *testing.T) {
	for _, uri := range []string{"socks5://%s", "socks4://%s", "ssh://u:p@%s"} {
		t.Run(uri, func(t *testing.T) {
			system := testutils.System{}
			remote, err := permuteproxy.ParseURI(strings.Replace(uri, "%s", "127.0.0.1:0", 1))
			if err != nil {
				t.Fatal(err)
			}
			remoteAddr := run(t, permuteproxy.ServerEngine{Base: system, Upstream: system}, remote)
			remote.Endpoint.Address = remoteAddr
			client, err := permuteproxy.ClientEngine{Base: system}.Client(remote)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.(io.Closer).Close() })

			// An http proxy served through the client is bound by the remote proxy.
			local, err := permuteproxy.ParseURI("http://127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			local.Endpoint.Address = run(t, permuteproxy.ServerEngine{Base: client, Upstream: system}, local)
			via, err := permuteproxy.ClientEngine{Base: system}.Client(local)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { via.(io.Closer).Close() })

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			target := testutils.ServeEcho(t, ln).String()
			for range 2 {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := via.DialContext(ctx, "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				// The echo may come back in pieces through this many hops.
				if _, err := conn.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
					t.Fatalf("Read = %q, %v; want ping", buf, err)
				}
			}
		})
	}
}
