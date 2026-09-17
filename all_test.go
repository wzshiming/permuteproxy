package permuteproxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/all"
	"github.com/wzshiming/permuteproxy/protocols/local"
)

var system permuteproxy.Network = permuteproxy.NetworkFuncs{
	DialContextFunc:  (&net.Dialer{}).DialContext,
	ListenFunc:       (&net.ListenConfig{}).Listen,
	ListenPacketFunc: (&net.ListenConfig{}).ListenPacket,
}

// probe counts the operations a chain performs on an injected network and reports bound addresses.
type probe struct {
	permuteproxy.Network
	dials   atomic.Int32
	listens atomic.Int32
	bound   chan net.Addr
}

func newProbe(n permuteproxy.Network) *probe {
	return &probe{Network: n, bound: make(chan net.Addr, 1)}
}

func (p *probe) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	p.dials.Add(1)
	return p.Network.DialContext(ctx, network, address)
}

func (p *probe) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	ln, err := p.Network.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	p.listens.Add(1)
	select {
	case p.bound <- ln.Addr():
	default:
	}
	return ln, nil
}

func closeIf(v any) {
	if c, ok := v.(io.Closer); ok {
		c.Close()
	}
}

// start runs the server in the background; the returned channel yields Run's result once.
func start(t *testing.T, e permuteproxy.Engine, c permuteproxy.Chain) (permuteproxy.Server, <-chan error) {
	t.Helper()
	srv, err := e.Server(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		srv.Close()
		cancel()
	})
	return srv, done
}

func waitBound(t *testing.T, base *probe, done <-chan error) net.Addr {
	t.Helper()
	select {
	case addr := <-base.bound:
		return addr
	case err := <-done:
		t.Fatalf("server exited before binding: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not bind")
	}
	return nil
}

func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

func fetch(ctx context.Context, n permuteproxy.Network, url string) (string, error) {
	tr := &http.Transport{DialContext: n.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func reservePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func parse(t *testing.T, uri string) permuteproxy.Chain {
	t.Helper()
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func requireNetcat(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("cmd-nc rows need a POSIX nc listener")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skipf("nc executable unavailable: %v", err)
	}
}

// proxyRows is the stream URI matrix; port 0 and ./test.socks are rewritten per row.
var proxyRows = []string{
	"socks5+cmd-nc://127.0.0.1:0",
	"socks5+cmd-nc://u:p@127.0.0.1:0",
	"socks5+cmd-nc-unix://./test1.socks",
	"socks5+cmd-nc-unix://u:p@./test2.socks",
	"any://127.0.0.1:0",
	"any://u:p@127.0.0.1:0",
	"any+unix://./test.socks",
	"any+unix://u:p@./test.socks",
	"http://127.0.0.1:0",
	"http://u:p@127.0.0.1:0",
	"http+unix://./test.socks",
	"http+unix://u:p@./test.socks",
	"socks5://127.0.0.1:0",
	"socks5://u:p@127.0.0.1:0",
	"socks5+unix://./test.socks",
	"socks5+unix://u:p@./test.socks",
	"socks4://127.0.0.1:0",
	"socks4://u:p@127.0.0.1:0",
	"socks4+unix://./test.socks",
	"socks4+unix://u:p@./test.socks",
	"ssh://127.0.0.1:0",
	"ssh://u:p@127.0.0.1:0",
	"ssh+unix://./test.socks",
	"ssh+unix://u:p@./test.socks",
	"ss://127.0.0.1:0",
	"ss://aes-256-gcm:p@127.0.0.1:0",
	"ss+unix://./test.socks",
	"ss+unix://aes-256-gcm:p@./test.socks",
	"any+snappy://127.0.0.1:0",
	"any+snappy://u:p@127.0.0.1:0",
	"http+snappy://127.0.0.1:0",
	"http+snappy://u:p@127.0.0.1:0",
	"http+snappy+unix://./test.socks",
	"http+snappy+unix://u:p@./test.socks",
	"socks5+snappy://127.0.0.1:0",
	"socks5+snappy://u:p@127.0.0.1:0",
	"socks5+snappy+unix://./test.socks",
	"socks5+snappy+unix://u:p@./test.socks",
	"socks4+snappy://127.0.0.1:0",
	"socks4+snappy://u:p@127.0.0.1:0",
	"socks4+snappy+unix://./test.socks",
	"socks4+snappy+unix://u:p@./test.socks",
	"ssh+snappy://127.0.0.1:0",
	"ssh+snappy://u:p@127.0.0.1:0",
	"ssh+snappy+unix://./test.socks",
	"ssh+snappy+unix://u:p@./test.socks",
	"ss+snappy://127.0.0.1:0",
	"ss+snappy://aes-256-gcm:p@127.0.0.1:0",
	"ss+snappy+unix://./test.socks",
	"ss+snappy+unix://aes-256-gcm:p@./test.socks",
	"https://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"https://u:p@127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"http+tls://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"http+tls://u:p@127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
}

var anyClients = []string{"http", "socks4", "socks5", "ssh"}

func TestProxy(t *testing.T) {
	want := "OK"
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(want))
	}))
	t.Cleanup(target.Close)
	dir := t.TempDir()
	for i, uri := range proxyRows {
		t.Run(uri, func(t *testing.T) {
			c := parse(t, uri)
			command := strings.HasPrefix(c.Endpoint.Network, "cmd")
			if command {
				requireNetcat(t)
			}
			switch c.Endpoint.Network {
			case "unix", "cmd-nc-unix":
				c.Endpoint.Address = filepath.Join(dir, fmt.Sprintf("%d.sock", i))
			case "cmd-nc":
				c.Endpoint.Address = reservePort(t)
			}
			base, upstream := newProbe(local.Network), newProbe(system)
			_, done := start(t, permuteproxy.Engine{Base: base, Upstream: upstream}, c)
			addr := waitBound(t, base, done)
			if c.Endpoint.Network == "" {
				c.Endpoint.Address = addr.String()
			}
			clients := []string{c.Layers[0].Scheme}
			if clients[0] == "any" {
				clients = anyClients
			}
			for _, scheme := range clients {
				t.Run(scheme, func(t *testing.T) {
					if scheme == "socks5" && c.Layers[0].Scheme == "any" && strings.Contains(uri, "snappy") {
						t.Skip("cmux drops a partial prefix match and the socks5 greeting arrives as two snappy frames")
					}
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					cc := c
					cc.Layers = append([]permuteproxy.Layer{{Scheme: scheme, Options: c.Layers[0].Options}}, c.Layers[1:]...)
					clientBase := newProbe(local.Network)
					n, err := permuteproxy.Engine{Base: clientBase}.Client(cc)
					if err != nil {
						t.Fatal(err)
					}
					defer closeIf(n)
					before := upstream.dials.Load()
					body, err := fetch(ctx, n, target.URL)
					// nc listeners bind only inside Accept, so command rows poll until the first request lands.
					for err != nil && command && ctx.Err() == nil {
						time.Sleep(20 * time.Millisecond)
						body, err = fetch(ctx, n, target.URL)
					}
					if err != nil {
						t.Fatal(err)
					}
					if body != want {
						t.Fatalf("got %q, want %q", body, want)
					}
					if got := upstream.dials.Load() - before; got != 1 {
						t.Fatalf("upstream dials = %d, want 1", got)
					}
					if got := clientBase.dials.Load(); got < 1 || (!command && got != 1) {
						t.Fatalf("client base dials = %d", got)
					}
				})
			}
			if got := base.listens.Load(); got != 1 {
				t.Fatalf("base listens = %d, want 1", got)
			}
		})
	}
}

func TestServerLifecycle(t *testing.T) {
	for _, uri := range []string{"http://127.0.0.1:0", "socks5://127.0.0.1:0", "ss://127.0.0.1:0", "any://127.0.0.1:0"} {
		t.Run(uri, func(t *testing.T) {
			c := parse(t, uri)
			t.Run("cancel", func(t *testing.T) {
				base := newProbe(system)
				srv, err := permuteproxy.Engine{Base: base}.Server(c)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- srv.Run(ctx) }()
				waitBound(t, base, done)
				cancel()
				waitDone(t, done)
			})
			t.Run("close", func(t *testing.T) {
				base := newProbe(system)
				srv, done := start(t, permuteproxy.Engine{Base: base}, c)
				addr := waitBound(t, base, done)
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
				waitDone(t, done)
				if err := srv.Close(); err != nil {
					t.Fatalf("second Close = %v", err)
				}
				if conn, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
					conn.Close()
					t.Fatal("listener still accepting after Close")
				}
			})
			t.Run("close before run", func(t *testing.T) {
				base := newProbe(system)
				srv, err := permuteproxy.Engine{Base: base}.Server(c)
				if err != nil {
					t.Fatal(err)
				}
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- srv.Run(context.Background()) }()
				waitDone(t, done)
				if got := base.listens.Load(); got != 0 {
					t.Fatalf("base listens = %d after Close, want 0", got)
				}
			})
		})
	}
}

func TestProxyRejectsBadCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("OK"))
	}))
	t.Cleanup(target.Close)
	tests := []struct {
		server string
		client permuteproxy.Options
	}{
		{"http://u:p@127.0.0.1:0", permuteproxy.Options{"username": "u", "password": "x"}},
		{"http://u:p@127.0.0.1:0", nil},
		{"socks5://u:p@127.0.0.1:0", permuteproxy.Options{"username": "u", "password": "x"}},
		{"socks5://u:p@127.0.0.1:0", nil},
		{"socks4://u@127.0.0.1:0", permuteproxy.Options{"username": "x"}},
		{"ssh://u:p@127.0.0.1:0", permuteproxy.Options{"username": "u", "password": "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.server+"/"+tt.client["username"], func(t *testing.T) {
			c := parse(t, tt.server)
			base := newProbe(system)
			_, done := start(t, permuteproxy.Engine{Base: base}, c)
			c.Endpoint.Address = waitBound(t, base, done).String()
			c.Layers[0].Options = tt.client
			n, err := permuteproxy.Engine{}.Client(c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if body, err := fetch(ctx, n, target.URL); err == nil {
				t.Fatalf("request with bad credentials succeeded: %q", body)
			}
		})
	}
}

func TestClientRefusesPacket(t *testing.T) {
	for _, uri := range []string{"http://127.0.0.1:1", "socks5://127.0.0.1:1", "socks4://127.0.0.1:1", "ssh://127.0.0.1:1", "ss://127.0.0.1:1"} {
		t.Run(uri, func(t *testing.T) {
			base := newProbe(system)
			n, err := permuteproxy.Engine{Base: base}.Client(parse(t, uri))
			if err != nil {
				t.Fatal(err)
			}
			defer closeIf(n)
			if _, err := n.DialContext(context.Background(), "udp", "127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
				t.Fatalf("DialContext(udp) = %v, want ErrUnsupported", err)
			}
			if got := base.dials.Load(); got != 0 {
				t.Fatalf("base dials = %d, want 0", got)
			}
		})
	}
}
