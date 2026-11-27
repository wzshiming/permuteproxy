package all_test

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
	_ "github.com/wzshiming/permuteproxy/protocols/all"
	"github.com/wzshiming/permuteproxy/protocols/command"
	"github.com/wzshiming/permuteproxy/protocols/local"
	"github.com/wzshiming/permuteproxy/protocols/netcat"
)

// probe counts the operations a chain performs on an injected network, reports bound addresses and
// accepted connections, signals closes of the sockets it handed out, and counts the Close calls a
// borrowed network must never see.
type probe struct {
	permuteproxy.Network
	dials        atomic.Int32
	listens      atomic.Int32
	packets      atomic.Int32
	closes       atomic.Int32
	bound        chan net.Addr
	boundPacket  chan net.Addr
	accepted     chan struct{}
	packetClosed chan struct{}
}

// bundled sends each call to the bundled implementation of its network, as a nil Base does; a probe counts over it.
type bundled struct{}

func (bundled) of(network string) permuteproxy.Network {
	switch {
	case network == "cmd":
		return command.Network
	case strings.HasPrefix(network, "cmd-nc"):
		return netcat.Network
	}
	return local.Network
}

func (b bundled) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return b.of(network).DialContext(ctx, network, address)
}

func (b bundled) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return b.of(network).Listen(ctx, network, address)
}

func (b bundled) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return b.of(network).ListenPacket(ctx, network, address)
}

func newProbe(n permuteproxy.Network) *probe {
	return &probe{Network: n, bound: make(chan net.Addr, 1), boundPacket: make(chan net.Addr, 1), accepted: make(chan struct{}, 64), packetClosed: make(chan struct{}, 64)}
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
	return acceptProbe{ln, p.accepted}, nil
}

func (p *probe) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := p.Network.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	p.packets.Add(1)
	select {
	case p.boundPacket <- pc.LocalAddr():
	default:
	}
	return closeSignal{pc, p.packetClosed}, nil
}

func (p *probe) Close() error {
	p.closes.Add(1)
	return nil
}

type closeSignal struct {
	net.PacketConn
	closed chan struct{}
}

func (c closeSignal) Close() error {
	err := c.PacketConn.Close()
	select {
	case c.closed <- struct{}{}:
	default:
	}
	return err
}

type acceptProbe struct {
	net.Listener
	accepted chan struct{}
}

func (l acceptProbe) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		select {
		case l.accepted <- struct{}{}:
		default:
		}
	}
	return conn, err
}

func closeIf(v any) {
	if c, ok := v.(io.Closer); ok {
		c.Close()
	}
}

// start runs the server in the background; the returned channel yields Run's result once.
func start(t *testing.T, e permuteproxy.ServerEngine, c permuteproxy.Chain) (permuteproxy.Server, <-chan error) {
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

func waitBoundPacket(t *testing.T, base *probe, done <-chan error) net.Addr {
	t.Helper()
	select {
	case addr := <-base.boundPacket:
		return addr
	case err := <-done:
		t.Fatalf("server exited before binding a socket: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not bind a socket")
	}
	return nil
}

func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	if err := testutils.Wait(t, done, "Run to return"); err != nil {
		t.Fatalf("Run returned %v", err)
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
	"any+lz4://127.0.0.1:0",
	"any+lz4://u:p@127.0.0.1:0",
	"http+lz4://127.0.0.1:0",
	"http+lz4://u:p@127.0.0.1:0",
	"http+lz4+unix://./test.socks",
	"http+lz4+unix://u:p@./test.socks",
	"socks5+lz4://127.0.0.1:0",
	"socks5+lz4://u:p@127.0.0.1:0",
	"socks5+lz4+unix://./test.socks",
	"socks5+lz4+unix://u:p@./test.socks",
	"socks4+lz4://127.0.0.1:0",
	"socks4+lz4://u:p@127.0.0.1:0",
	"socks4+lz4+unix://./test.socks",
	"socks4+lz4+unix://u:p@./test.socks",
	"ssh+lz4://127.0.0.1:0",
	"ssh+lz4://u:p@127.0.0.1:0",
	"ssh+lz4+unix://./test.socks",
	"ssh+lz4+unix://u:p@./test.socks",
	"ss+lz4://127.0.0.1:0",
	"ss+lz4://aes-256-gcm:p@127.0.0.1:0",
	"ss+lz4+unix://./test.socks",
	"ss+lz4+unix://aes-256-gcm:p@./test.socks",
	"any+zstd://127.0.0.1:0",
	"any+zstd://u:p@127.0.0.1:0",
	"http+zstd://127.0.0.1:0",
	"http+zstd://u:p@127.0.0.1:0",
	"http+zstd+unix://./test.socks",
	"http+zstd+unix://u:p@./test.socks",
	"socks5+zstd://127.0.0.1:0",
	"socks5+zstd://u:p@127.0.0.1:0",
	"socks5+zstd+unix://./test.socks",
	"socks5+zstd+unix://u:p@./test.socks",
	"socks4+zstd://127.0.0.1:0",
	"socks4+zstd://u:p@127.0.0.1:0",
	"socks4+zstd+unix://./test.socks",
	"socks4+zstd+unix://u:p@./test.socks",
	"ssh+zstd://127.0.0.1:0",
	"ssh+zstd://u:p@127.0.0.1:0",
	"ssh+zstd+unix://./test.socks",
	"ssh+zstd+unix://u:p@./test.socks",
	"ss+zstd://127.0.0.1:0",
	"ss+zstd://aes-256-gcm:p@127.0.0.1:0",
	"ss+zstd+unix://./test.socks",
	"ss+zstd+unix://aes-256-gcm:p@./test.socks",
	"https://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"https://u:p@127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"http+tls://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"http+tls://u:p@127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"socks5+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"http+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"socks4+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"ssh+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"any+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"ss+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"socks5+snappy+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"socks5+lz4+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	"socks5+zstd+quic://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
}

// selfSigned has a tls or quic server sign its own certificate and a client skip verifying it.
var selfSigned = permuteproxy.Options{"tls_self_signed": "true", "tls_skip_verify": "true"}

// proxyChains are matrix rows no URI writes, as a URI hands tls_* keys only to the outer of tls and quic.
var proxyChains = []matrixRow{
	{"socks5+tls+quic://127.0.0.1:0", permuteproxy.Chain{
		Layers:   []permuteproxy.Layer{{Scheme: "socks5"}, {Scheme: "tls", Options: selfSigned}, {Scheme: "quic", Options: selfSigned}},
		Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:0"},
	}},
}

var anyClients = []string{"http", "socks4", "socks5", "ssh"}

// matrixRow is a chain of the stream matrix and the name its subtest runs under.
type matrixRow struct {
	name  string
	chain permuteproxy.Chain
}

func TestProxy(t *testing.T) {
	want := "OK"
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(want))
	}))
	t.Cleanup(target.Close)
	dir := t.TempDir()
	rows := make([]matrixRow, 0, len(proxyRows)+len(proxyChains))
	for _, uri := range proxyRows {
		rows = append(rows, matrixRow{uri, parse(t, uri)})
	}
	rows = append(rows, proxyChains...)
	for i, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			c := row.chain
			command := strings.HasPrefix(c.Endpoint.Network, "cmd")
			if command {
				requireNetcat(t)
			}
			switch c.Endpoint.Network {
			case "unix", "cmd-nc-unix":
				c.Endpoint.Address = filepath.Join(dir, fmt.Sprintf("%d.sock", i))
			case "cmd-nc":
				c.Endpoint.Address = testutils.ReservePort(t)
			}
			// A quic row's server binds a udp socket at port 0, not a listener.
			overUDP := c.Layers[len(c.Layers)-1].Scheme == "quic"
			base, upstream := newProbe(bundled{}), newProbe(testutils.System{})
			_, done := start(t, permuteproxy.ServerEngine{Base: base, Upstream: upstream}, c)
			bound := waitBound
			if overUDP {
				bound = waitBoundPacket
			}
			addr := bound(t, base, done)
			if c.Endpoint.Network == "" {
				c.Endpoint.Address = addr.String()
			}
			clients := []string{c.Layers[0].Scheme}
			if clients[0] == "any" {
				clients = anyClients
			}
			for _, scheme := range clients {
				t.Run(scheme, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					cc := c
					cc.Layers = append([]permuteproxy.Layer{{Scheme: scheme, Options: c.Layers[0].Options}}, c.Layers[1:]...)
					clientBase := newProbe(bundled{})
					n, err := permuteproxy.ClientEngine{Base: clientBase, Local: clientBase}.Client(cc)
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
					if overUDP {
						if got := clientBase.packets.Load(); got != 1 || clientBase.dials.Load() != 0 {
							t.Fatalf("client base packets = %d, dials = %d; want one socket", got, clientBase.dials.Load())
						}
					} else if got := clientBase.dials.Load(); got < 1 || (!command && got != 1) {
						t.Fatalf("client base dials = %d", got)
					}
				})
			}
			if overUDP {
				if got := base.packets.Load(); got != 1 || base.listens.Load() != 0 {
					t.Fatalf("base packets = %d, listens = %d; want one socket", got, base.listens.Load())
				}
			} else if got := base.listens.Load(); got != 1 {
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
				base := newProbe(testutils.System{})
				srv, err := permuteproxy.ServerEngine{Base: base}.Server(c)
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
				base := newProbe(testutils.System{})
				srv, done := start(t, permuteproxy.ServerEngine{Base: base}, c)
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
				base := newProbe(testutils.System{})
				srv, err := permuteproxy.ServerEngine{Base: base}.Server(c)
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

// greetings are the leading handshake bytes a client sends before stalling, per proxy scheme.
var greetings = map[string]string{"http": "GET ", "socks4": "\x04", "socks5": "\x05", "ss": "\x01", "ssh": "SSH-", "any": "\x05"}

// readErr drains conn and reports the error that ends it, failing if none arrives.
func readErr(t *testing.T, conn net.Conn) error {
	t.Helper()
	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := conn.Read(buf); err != nil {
				got <- err
				return
			}
		}
	}()
	select {
	case err := <-got:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("connection survived the server stop")
		return nil
	}
}

// holdingTarget accepts connections and keeps them silent until the test ends.
func holdingTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	return ln.Addr().String()
}

// connect opens a client connection to the proxy at c in the given state: idle sends nothing,
// partial sends a truncated greeting, tunnel completes the proxy handshake towards target.
func connect(t *testing.T, ctx context.Context, c permuteproxy.Chain, state, target string) net.Conn {
	t.Helper()
	scheme := c.Layers[0].Scheme
	if state == "tunnel" {
		if scheme == "any" {
			c.Layers = append([]permuteproxy.Layer{{Scheme: "socks5", Options: c.Layers[0].Options}}, c.Layers[1:]...)
		}
		n, err := permuteproxy.ClientEngine{}.Client(c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeIf(n) })
		conn, err := n.DialContext(ctx, "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	c.Layers = c.Layers[1:]
	if c.Endpoint.Network == "" {
		c.Endpoint.Network = "tcp"
	}
	tr, err := permuteproxy.TransportEngine{}.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if state == "partial" {
		if _, err := conn.Write([]byte(greetings[scheme])); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

func TestServerStopReleasesConns(t *testing.T) {
	target := holdingTarget(t)
	rows := []string{
		"http://127.0.0.1:0",
		"socks4://127.0.0.1:0",
		"socks5://127.0.0.1:0",
		"ss://127.0.0.1:0",
		"ss://aes-256-gcm:p@127.0.0.1:0",
		"ssh://127.0.0.1:0",
		"any://127.0.0.1:0",
		"any+snappy://127.0.0.1:0",
		"socks5+snappy://127.0.0.1:0",
		"any+lz4://127.0.0.1:0",
		"socks5+lz4://127.0.0.1:0",
		"any+zstd://127.0.0.1:0",
		"socks5+zstd://127.0.0.1:0",
		"socks5+tls://127.0.0.1:0?tls_skip_verify=true&tls_self_signed=true",
	}
	for _, uri := range rows {
		c := parse(t, uri)
		for _, state := range []string{"idle", "partial", "tunnel"} {
			for _, stop := range []string{"close", "cancel"} {
				t.Run(uri+"/"+state+"/"+stop, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					base, upstream := newProbe(testutils.System{}), newProbe(testutils.System{})
					srv, err := permuteproxy.ServerEngine{Base: base, Upstream: upstream}.Server(c)
					if err != nil {
						t.Fatal(err)
					}
					runCtx, stopRun := context.WithCancel(ctx)
					done := make(chan error, 1)
					go func() { done <- srv.Run(runCtx) }()
					t.Cleanup(func() {
						srv.Close()
						stopRun()
					})
					cc := c
					cc.Endpoint.Address = waitBound(t, base, done).String()
					conn := connect(t, ctx, cc, state, target)
					defer conn.Close()
					select {
					case <-base.accepted:
					case <-time.After(5 * time.Second):
						t.Fatal("server did not accept the connection")
					}
					if stop == "close" {
						if err := srv.Close(); err != nil {
							t.Fatal(err)
						}
					} else {
						stopRun()
					}
					waitDone(t, done)
					if err := readErr(t, conn); err == nil {
						t.Fatal("client read succeeded after the server stopped")
					}
					if base.closes.Load() != 0 || upstream.closes.Load() != 0 {
						t.Fatalf("borrowed networks closed: base %d upstream %d", base.closes.Load(), upstream.closes.Load())
					}
				})
			}
		}
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
			base := newProbe(testutils.System{})
			_, done := start(t, permuteproxy.ServerEngine{Base: base}, c)
			c.Endpoint.Address = waitBound(t, base, done).String()
			c.Layers[0].Options = tt.client
			n, err := permuteproxy.ClientEngine{}.Client(c)
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
	for _, uri := range []string{"http://127.0.0.1:1", "socks4://127.0.0.1:1"} {
		t.Run(uri, func(t *testing.T) {
			base := newProbe(testutils.System{})
			n, err := permuteproxy.ClientEngine{Base: base, Local: base}.Client(parse(t, uri))
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

func TestCommandNetworksRefusedByABaseWithoutCmd(t *testing.T) {
	under := &testutils.CountingNetwork{}
	client, err := permuteproxy.ClientEngine{Base: under, Local: under}.Client(permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "socks5"}}, Endpoint: permuteproxy.Endpoint{Network: "tcp", Address: "127.0.0.1:1080"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.(io.Closer).Close()
	for _, tt := range []struct {
		network, address string
		plane            permuteproxy.Plane
	}{
		{"cmd-nc", "127.0.0.1:80", permuteproxy.Stream},
		{"cmd-nc-udp", "127.0.0.1:53", permuteproxy.Packet},
	} {
		tr, err := permuteproxy.TransportEngine{Base: client}.Transport(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: tt.network, Address: tt.address}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Dial(context.Background(), tt.plane); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Errorf("Dial %s through a socks5 client = %v, want ErrUnsupported", tt.network, err)
		}
	}
	if got := under.Calls.Load(); got != 0 {
		t.Fatalf("the socks5 client reached its server: %d calls", got)
	}
}
