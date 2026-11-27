package netcat_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local"
	_ "github.com/wzshiming/permuteproxy/protocols/netcat"
)

// recorder is a base whose network cmd records each command line instead of running it.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) record(network, address string) error {
	if network != "cmd" {
		return permuteproxy.ErrUnsupported
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, address)
	return nil
}

func (r *recorder) network() permuteproxy.Network {
	return permuteproxy.NetworkFuncs{
		DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
			if err := r.record(network, address); err != nil {
				return nil, err
			}
			conn, peer := net.Pipe()
			peer.Close()
			return conn, nil
		},
		ListenFunc: func(_ context.Context, network, address string) (net.Listener, error) {
			if err := r.record(network, address); err != nil {
				return nil, err
			}
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
}

func (r *recorder) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lines[len(r.lines)-1]
}

func client(t *testing.T, uri string, r *recorder) permuteproxy.Network {
	t.Helper()
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatalf("%s: %v", uri, err)
	}
	n, err := permuteproxy.ClientEngine{Base: r.network()}.Client(c)
	if err != nil {
		t.Fatalf("%s: %v", uri, err)
	}
	return n
}

func TestCommandLines(t *testing.T) {
	for _, tt := range []struct {
		uri, network, target, dial, listen string
	}{
		{"nc:", "tcp", "example.com:443", "nc example.com 443", "nc -l example.com 443"},
		{"netcat:", "tcp", "example.com:443", "nc example.com 443", "nc -l example.com 443"},
		{"nc:", "tcp4", "127.0.0.1:80", "nc -4 127.0.0.1 80", "nc -4 -l 127.0.0.1 80"},
		{"nc:", "tcp6", "[::1]:80", "nc -6 ::1 80", "nc -6 -l ::1 80"},
		{"nc:", "unix", "/run/proxy.sock", "nc -U /run/proxy.sock", "nc -Ul /run/proxy.sock"},
		{"nc:ssh jump", "tcp", "host:22", "ssh jump nc host 22", "ssh jump nc -l host 22"},
		{"nc: ssh jump ", "unix", "./x.sock", "ssh jump nc -U ./x.sock", "ssh jump nc -Ul ./x.sock"},
		{"nc:env A=100%h", "tcp", "host:1", "env A=100%h nc host 1", "env A=100%h nc -l host 1"},
	} {
		r := &recorder{}
		n := client(t, tt.uri, r)
		conn, err := n.DialContext(context.Background(), tt.network, tt.target)
		if err != nil {
			t.Fatalf("%s: dial %s %s: %v", tt.uri, tt.network, tt.target, err)
		}
		conn.Close()
		if got := r.last(); got != tt.dial {
			t.Errorf("%s: dial %s %s ran %q, want %q", tt.uri, tt.network, tt.target, got, tt.dial)
		}
		ln, err := n.Listen(context.Background(), tt.network, tt.target)
		if err != nil {
			t.Fatalf("%s: listen %s %s: %v", tt.uri, tt.network, tt.target, err)
		}
		ln.Close()
		if got := r.last(); got != tt.listen {
			t.Errorf("%s: listen %s %s ran %q, want %q", tt.uri, tt.network, tt.target, got, tt.listen)
		}
	}
}

func TestDatagramCommandLines(t *testing.T) {
	for _, tt := range []struct {
		uri, network, target, want string
	}{
		{"nc:", "udp", "example.com:53", "nc -u -w 30 example.com 53"},
		{"nc:", "udp4", "127.0.0.1:53", "nc -4 -u -w 30 127.0.0.1 53"},
		{"nc:", "udp6", "[::1]:53", "nc -6 -u -w 30 ::1 53"},
		{"nc:ssh jump", "udp", "host:53", "ssh jump nc -u -w 30 host 53"},
		{"nc:", "unixgram", "/run/x.sock", "nc -U -u -w 30 /run/x.sock"},
		{"nc:ssh jump", "unixgram", "./x.sock", "ssh jump nc -U -u -w 30 ./x.sock"},
	} {
		base := strings.TrimRight(tt.network, "46")
		r := &recorder{}
		n := client(t, tt.uri, r)
		conn, err := n.DialContext(context.Background(), tt.network, tt.target)
		if err != nil {
			t.Fatalf("%s: dial %s %s: %v", tt.uri, tt.network, tt.target, err)
		}
		if _, ok := conn.(net.PacketConn); !ok {
			t.Errorf("%s: dial %s gave no net.PacketConn", tt.uri, tt.network)
		}
		if got := conn.RemoteAddr(); got.Network() != base || got.String() != tt.target {
			t.Errorf("%s: peer = %s %s, want %s %s", tt.uri, got.Network(), got, base, tt.target)
		}
		conn.Close()
		if got := r.last(); got != tt.want {
			t.Errorf("%s: dial %s %s ran %q, want %q", tt.uri, tt.network, tt.target, got, tt.want)
		}
	}
}

// A datagram socket at an address of its own is one nc -u -l, good for a single peer.
func TestDatagramListenCommandLines(t *testing.T) {
	for _, tt := range []struct {
		uri, network, address, want string
	}{
		{"nc:", "udp", "127.0.0.1:53", "nc -u -l 127.0.0.1 53"},
		{"nc:", "udp4", "0.0.0.0:53", "nc -4 -u -l 0.0.0.0 53"},
		{"nc:", "udp6", "[::1]:53", "nc -6 -u -l ::1 53"},
		{"nc:", "udp", "127.0.0.1:0", "nc -u -l 127.0.0.1 0"},
		{"nc:ssh jump", "udp", "host:53", "ssh jump nc -u -l host 53"},
		{"nc:", "unixgram", "/run/x.sock", "nc -U -u -l /run/x.sock"},
		{"nc:ssh jump", "unixgram", "./x.sock", "ssh jump nc -U -u -l ./x.sock"},
	} {
		base := strings.TrimRight(tt.network, "46")
		r := &recorder{}
		n := client(t, tt.uri, r)
		pc, err := n.ListenPacket(context.Background(), tt.network, tt.address)
		if err != nil {
			t.Fatalf("%s: listen packet %s %s: %v", tt.uri, tt.network, tt.address, err)
		}
		if got := pc.LocalAddr(); got.Network() != base || got.String() != tt.address {
			t.Errorf("%s: LocalAddr = %s %s, want %s %s", tt.uri, got.Network(), got, base, tt.address)
		}
		pc.Close()
		if got := r.last(); got != tt.want {
			t.Errorf("%s: listen packet %s %s ran %q, want %q", tt.uri, tt.network, tt.address, got, tt.want)
		}
	}
	// An unspecified host with port 0 names no address to bind, so no nc runs until a peer is written to.
	r := &recorder{}
	pc, err := client(t, "nc:", r).ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if len(r.lines) != 0 {
		t.Errorf("listen packet udp :0 ran %q, want no command", r.lines)
	}
}

func TestRefuses(t *testing.T) {
	r := &recorder{}
	n := client(t, "nc:", r)
	ctx := context.Background()
	if _, err := n.DialContext(ctx, "ip", "127.0.0.1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("dial ip: err = %v, want ErrUnsupported", err)
	}
	if _, err := n.Listen(ctx, "unixgram", "./x.sock"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("listen unixgram: err = %v, want ErrUnsupported", err)
	}
	if _, err := n.Listen(ctx, "udp", "host:53"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("listen udp: err = %v, want ErrUnsupported", err)
	}
	for network, address := range map[string]string{"tcp": ":0", "unix": "./x.sock"} {
		if _, err := n.ListenPacket(ctx, network, address); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Errorf("listen packet %s %s: err = %v, want ErrUnsupported", network, address, err)
		}
	}
	for network, address := range map[string]string{"tcp": "ho;st:1", "udp": "ho;st:1", "unix": "a b.sock", "unixgram": "a b.sock"} {
		if _, err := n.DialContext(ctx, network, address); err == nil {
			t.Errorf("dial %s %s succeeded with a value a shell would not read as plain text", network, address)
		}
	}
	if len(r.lines) != 0 {
		t.Errorf("refused calls ran %q", r.lines)
	}
	if _, err := permuteproxy.ParseURI("socks5+nc:"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Errorf("socks5+nc: err = %v, want ErrInvalidChain", err)
	}
	if l, ok := n.(permuteproxy.LossyNetwork); !ok || !l.Lossy("udp") || !l.Lossy("unixgram") || l.Lossy("tcp") || l.Lossy("unix") {
		t.Error("client does not report udp and unixgram alone as lossy")
	}
}

// A client without a prefix listens at a unix socket through a base that cleans up after nc.
func TestUnixListenPrefersTheCleaningBase(t *testing.T) {
	var calls []string
	base := permuteproxy.NetworkFuncs{ListenFunc: func(_ context.Context, network, address string) (net.Listener, error) {
		calls = append(calls, network+" "+address)
		return net.Listen("tcp", "127.0.0.1:0")
	}}
	for uri, want := range map[string]string{"nc:": "cmd-nc-unix ./x.sock", "nc:ssh jump": "cmd ssh jump nc -Ul ./x.sock"} {
		c, err := permuteproxy.ParseURI(uri)
		if err != nil {
			t.Fatal(err)
		}
		n, err := permuteproxy.ClientEngine{Base: base}.Client(c)
		if err != nil {
			t.Fatal(err)
		}
		calls = nil
		ln, err := n.Listen(context.Background(), "unix", "./x.sock")
		if err != nil {
			t.Fatal(err)
		}
		ln.Close()
		if len(calls) != 1 || calls[0] != want {
			t.Errorf("%s: listen unix asked the base for %q, want %q", uri, calls, want)
		}
	}
}

func TestURIRoundTrip(t *testing.T) {
	for _, uri := range []string{"nc:", "netcat:", "nc:ssh%20jump"} {
		c, err := permuteproxy.ParseURI(uri)
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if got, err := c.URI(); err != nil || got != uri {
			t.Errorf("%s: URI() = %q, %v", uri, got, err)
		}
	}
}

// TestDialThroughNetcat reaches an echo listener through the system's nc.
func TestDialThroughNetcat(t *testing.T) {
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc on PATH")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	n, err := permuteproxy.NewClient("nc:")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := n.DialContext(ctx, "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

// TestDatagramsThroughNetcat reaches a udp echo through the system's nc, dialed and from a datagram socket.
func TestDatagramsThroughNetcat(t *testing.T) {
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc on PATH")
	}
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()
	n, err := permuteproxy.NewClient("nc:")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := n.DialContext(ctx, "udp4", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got, err := conn.Read(buf); err != nil || string(buf[:got]) != "ping" {
		t.Fatalf("dialed echo = %q, %v", buf[:got], err)
	}
	pc, err := n.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.WriteTo([]byte("pong"), echo.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:got]) != "pong" || from.String() != echo.LocalAddr().String() {
		t.Fatalf("socket echo = %q from %v, %v", buf[:got], from, err)
	}
}

// TestListenThroughNetcat accepts at a unix socket through the system's nc and leaves no socket file.
func TestListenThroughNetcat(t *testing.T) {
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc on PATH")
	}
	dir, err := os.MkdirTemp("", "nc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s.sock")
	n, err := permuteproxy.NewClient("nc:")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := n.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		// nc binds some time after Accept started it.
		for i := 0; i < 200; i++ {
			conn, err := net.Dial("unix", path)
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			conn.Write([]byte("ping"))
			io.Copy(io.Discard, conn)
			conn.Close()
			return
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("accepted conn read %q, %v", buf, err)
	}
	conn.Close()
	ln.Close()
	for i := 0; i < 400; i++ {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("socket file left behind after the connection and listener closed")
}

// TestUnixDatagramsThroughNetcat dials a unixgram echo and serves a unixgram peer through the system's nc.
func TestUnixDatagramsThroughNetcat(t *testing.T) {
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc on PATH")
	}
	dir, err := os.MkdirTemp("", "nc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	n, err := permuteproxy.NewClient("nc:")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := make([]byte, 64)

	echoPath := filepath.Join(dir, "echo.sock")
	echo, err := net.ListenPacket("unixgram", echoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()
	conn, err := n.DialContext(ctx, "unixgram", echoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got, err := conn.Read(buf); err != nil || string(buf[:got]) != "ping" {
		t.Fatalf("dialed echo = %q, %v", buf[:got], err)
	}

	path := filepath.Join(dir, "listen.sock")
	pc, err := n.ListenPacket(ctx, "unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		got, from, err := pc.ReadFrom(buf)
		if err == nil && string(buf[:got]) != "ping" {
			err = errors.New("read " + string(buf[:got]))
		}
		if err == nil {
			_, err = pc.WriteTo([]byte("pong"), from)
		}
		served <- err
	}()
	// The peer binds a path of its own, where nc's answer arrives.
	peer, err := net.ListenPacket("unixgram", filepath.Join(dir, "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	// nc binds some time after ListenPacket started it; a datagram sent before that is refused, not lost.
	for i := 0; ; i++ {
		if _, err = peer.WriteTo([]byte("ping"), &net.UnixAddr{Net: "unixgram", Name: path}); err == nil {
			break
		}
		if i == 200 {
			t.Fatalf("nc never bound %s: %v", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	if got, _, err := peer.ReadFrom(buf); err != nil || string(buf[:got]) != "pong" {
		t.Fatalf("peer read %q, %v", buf[:got], err)
	}
}
