package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// hostKeyPEM is the host key of the servers under test, so that none generates an RSA key.
var hostKeyPEM = func() []byte {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(block)
}()

// hostKey is hostKeyPEM as the hostkey_data option carries it.
var hostKey = base64.URLEncoding.EncodeToString(hostKeyPEM)

func init() {
	// A probe gives up sooner here, so that a silent connection goes within a second.
	keepAliveTimeout = time.Second
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// echoTarget accepts tcp conns and echoes what each sends.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// firehose accepts tcp conns and writes to each until it fails.
func firehose(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 32<<10)
				for {
					if _, err := conn.Write(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// recv waits for a value from ch, failing the test after a while.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

// roundTrip writes msg and expects want back, reading aside since ssh conns refuse deadlines.
func roundTrip(t *testing.T, conn net.Conn, msg, want string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	got := make([]byte, len(want))
	go func() {
		_, err := io.ReadFull(conn, got)
		read <- err
	}()
	if err := recv(t, read, "the reply to "+msg); err != nil || string(got) != want {
		t.Fatalf("read %q, %v; want %q", got, err, want)
	}
}

func TestURIKeepsNameAndKeys(t *testing.T) {
	uri := "ssh://u:p@127.0.0.1:1?authorized_data=a&authorized_file=b&hostkey_data=c&hostkey_file=d&identity_data=e&identity_file=f"
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	want := []permuteproxy.Layer{{Scheme: "ssh", Options: permuteproxy.Options{
		"username": "u", "password": "p",
		"authorized_data": "a", "authorized_file": "b", "hostkey_data": "c", "hostkey_file": "d", "identity_data": "e", "identity_file": "f",
	}}}
	if !reflect.DeepEqual(c.Layers, want) {
		t.Fatalf("ParseURI(%q).Layers = %+v, want %+v", uri, c.Layers, want)
	}
	if back, err := c.URI(); back != uri || err != nil {
		t.Fatalf("URI() = %q, %v, want %q", back, err, uri)
	}
	if _, err := permuteproxy.ParseURI("ssh://127.0.0.1:1?bogus=1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Fatalf("ParseURI with an undeclared option = %v, want ErrInvalidChain", err)
	}
}

func TestClientRefusesUnixgramAndListen(t *testing.T) {
	ctx := context.Background()
	base := &testutils.CountingNetwork{}
	n, err := permuteproxy.Engine{Base: base}.Client(permuteproxy.Chain{Layers: []permuteproxy.Layer{{Scheme: "ssh"}}, Endpoint: permuteproxy.Endpoint{Address: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DialContext(ctx, "unixgram", "./test.sock"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("DialContext(unixgram) = %v, want ErrUnsupported", err)
	}
	for _, network := range []string{"tcp", "unix"} {
		if _, err := n.Listen(ctx, network, "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
			t.Fatalf("Listen(%s) = %v, want ErrUnsupported", network, err)
		}
	}
	if got := base.Calls.Load(); got != 0 {
		t.Fatalf("base calls = %d, want 0", got)
	}
}

func TestFuncsTunnelOverInnerToUpstream(t *testing.T) {
	opts := permuteproxy.Options{"username": "u", "password": "p"}
	server, err := NewServer(permuteproxy.Options{"username": "u", "password": "p", "hostkey_data": hostKey})
	if err != nil {
		t.Fatal(err)
	}
	target, ln := echoTarget(t), listen(t)
	dials := make(chan string, 1)
	upstream := permuteproxy.NetworkFuncs{DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		dials <- network + " " + address
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln, upstream) }()
	defer func() {
		ln.Close()
		<-done
	}()
	client, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	inner := permuteproxy.TransportFuncs{Plane: permuteproxy.Stream, DialFunc: func(ctx context.Context, _ permuteproxy.Plane) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}}
	conn, err := client.Dial(ctx, inner, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "ping")
	if got, want := recv(t, dials, "the upstream dial"), "tcp "+target; got != want {
		t.Fatalf("upstream dial = %q, want %q", got, want)
	}
}

func TestFailedTargetsKeepTheConnection(t *testing.T) {
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
	ctx := timeout(t)
	conn, err := n.DialContext(ctx, "cmd", "relay x")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pc, err := n.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	peer := netutils.NewNetAddr("udp", "198.51.100.7:53")
	exchange := func(msg string) {
		t.Helper()
		if _, err := pc.WriteTo([]byte(msg), peer); err != nil {
			t.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 256)
		got, _, err := pc.ReadFrom(buf)
		if want := "nc -u -w 30 198.51.100.7 53|" + msg; err != nil || string(buf[:got]) != want {
			t.Fatalf("udp reply %q, %v; want %q", buf[:got], err, want)
		}
	}
	exchange("hi")
	ln := listen(t)
	refused := ln.Addr().String()
	ln.Close()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	// An unreachable target, a malformed address or an ended ctx is no failure of the connection.
	for _, d := range []struct {
		ctx              context.Context
		network, address string
	}{
		{ctx, "tcp", refused},
		{ctx, "unix", filepath.Join(t.TempDir(), "absent.sock")},
		{ctx, "tcp", "no-port"},
		{ctx, "tcp", "127.0.0.1:x"},
		{canceled, "tcp", echoTarget(t)},
	} {
		if c, err := n.DialContext(d.ctx, d.network, d.address); err == nil {
			c.Close()
			t.Fatalf("dial %s %s succeeded", d.network, d.address)
		}
	}
	roundTrip(t, conn, "ping", "relay x|ping")
	exchange("again")
	if got := base.dials.Load(); got != 1 {
		t.Fatalf("client dials = %d, want the first connection kept", got)
	}
}

func TestSilentConnectionIsReplacedAfterADialTimesOut(t *testing.T) {
	target := echoTarget(t)
	for _, tt := range []struct{ network, address, reply string }{
		{"cmd", "relay x", "relay x|ping"},
		{"tcp", target, "ping"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			base := &clientBase{}
			n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
			conn, err := n.DialContext(timeout(t), tt.network, tt.address)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			silent := base.mute()
			before := runtime.NumGoroutine()
			short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if conn, err := n.DialContext(short, tt.network, tt.address); !errors.Is(err, context.DeadlineExceeded) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("dial over the silent connection = %v, want context.DeadlineExceeded", err)
			}
			timedOut := time.Now()
			// More dials time out meanwhile, without a probe of their own.
			for range 8 {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				if conn, err := n.DialContext(ctx, tt.network, tt.address); err == nil {
					conn.Close()
				}
				cancel()
			}
			// The keep-alive the client sends then goes unanswered and nothing else arrives, so it drops the connection.
			recv(t, silent[0].closed, "the client to drop the silent connection")
			if waited := time.Since(timedOut); waited < keepAliveTimeout*9/10 || waited > 2*keepAliveTimeout {
				t.Fatalf("silent connection dropped %v after the dial timed out, want about %v", waited, keepAliveTimeout)
			}
			// What the timed-out dials left waiting ends with the connection.
			for wait := time.Now().Add(10 * time.Second); runtime.NumGoroutine() > before+4; time.Sleep(50 * time.Millisecond) {
				if time.Now().After(wait) {
					t.Fatalf("goroutines = %d once the silent connection was dropped, %d before the dials; want none left behind", runtime.NumGoroutine(), before)
				}
			}
			conn, err = n.DialContext(timeout(t), tt.network, tt.address)
			if err != nil {
				t.Fatalf("dial after the silent connection was dropped = %v", err)
			}
			defer conn.Close()
			roundTrip(t, conn, "ping", tt.reply)
			if got := base.dials.Load(); got != 2 {
				t.Fatalf("client dials = %d, want one reconnect", got)
			}
		})
	}
}

func TestDialTimingOutOverAHealthyConnectionKeepsIt(t *testing.T) {
	slow := slowTargets(newUpstream())
	for _, tt := range []struct{ network, address string }{
		{"tcp", "slow.invalid:1"},
		{"cmd", "stall"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			base := &clientBase{}
			n := dialServer(t, base, serveExec(t, slow), withCredentials())
			conn, err := n.DialContext(timeout(t), "cmd", "relay x")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if c, err := n.DialContext(short, tt.network, tt.address); !errors.Is(err, context.DeadlineExceeded) {
				if c != nil {
					c.Close()
				}
				t.Fatalf("dial to a slow target = %v, want context.DeadlineExceeded", err)
			}
			// The probe that dial started is answered, else the connection would be gone by now.
			select {
			case <-process(t, conn).Done():
				t.Fatal("the open cmd conn ended after a dial over its connection timed out")
			case <-time.After(keepAliveTimeout + 500*time.Millisecond):
			}
			roundTrip(t, conn, "ping", "relay x|ping")
			if got := base.dials.Load(); got != 1 {
				t.Fatalf("client dials = %d, want the connection kept", got)
			}
		})
	}
}

// slowTargets is up, except that a dial to slow.invalid:1 waits for its ctx to end.
func slowTargets(up permuteproxy.Network) permuteproxy.Network {
	return permuteproxy.NetworkFuncs{DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "slow.invalid:1" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return up.DialContext(ctx, network, address)
	}}
}

func TestDialTimingOutOverABusySlowLinkKeepsIt(t *testing.T) {
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, slowTargets(newUpstream())), withCredentials())
	ctx := timeout(t)
	conn, err := n.DialContext(ctx, "cmd", "relay x")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	download, err := n.DialContext(ctx, "tcp", firehose(t))
	if err != nil {
		t.Fatal(err)
	}
	defer download.Close()
	var received atomic.Int64
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := download.Read(buf)
			received.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	// What the server sends queues on the crawling link, the answer to a keep-alive included.
	release := base.throttle()
	defer release()
	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if c, err := n.DialContext(short, "tcp", "slow.invalid:1"); !errors.Is(err, context.DeadlineExceeded) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("dial to a slow target = %v, want context.DeadlineExceeded", err)
	}
	arrived := received.Load()
	select {
	case <-process(t, conn).Done():
		t.Fatal("the open cmd conn ended while the link was still delivering the download")
	case <-time.After(3 * keepAliveTimeout):
	}
	if received.Load() == arrived {
		t.Fatal("the download stalled, so no byte arrived to keep the probe waiting")
	}
	release()
	roundTrip(t, conn, "ping", "relay x|ping")
	if got := base.dials.Load(); got != 1 {
		t.Fatalf("client dials = %d, want the connection kept", got)
	}
}

func TestOversizedTargetsAreRefusedBeforeAnyIO(t *testing.T) {
	refuse := permuteproxy.NetworkFuncs{DialContextFunc: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("refused")
	}}
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, refuse), withCredentials())
	ctx := timeout(t)
	long, huge := strings.Repeat("a", 256), strings.Repeat("a", 300<<10)
	for _, d := range []struct{ network, address string }{
		{"tcp", long + ":80"},
		{"tcp", huge + ":80"},
		{"unix", "/" + long},
		{"unix", "/" + huge},
	} {
		if conn, err := n.DialContext(ctx, d.network, d.address); err == nil || errors.Is(err, permuteproxy.ErrUnsupported) {
			if conn != nil {
				conn.Close()
			}
			t.Errorf("dial %s to a %d-byte target = %.200v, want it refused", d.network, len(d.address), err)
		}
	}
	if got := base.dials.Load(); got != 0 {
		t.Fatalf("client dials = %d, want the targets refused before any I/O", got)
	}
	// A host of 255 bytes may be a name, so the server gets to refuse it.
	var refused *ssh.OpenChannelError
	if _, err := n.DialContext(ctx, "tcp", long[1:]+":80"); !errors.As(err, &refused) {
		t.Fatalf("dial tcp to a 255-byte host = %.200v, want the server to refuse it", err)
	}
}

func TestClosedClientRefusesWithoutReconnecting(t *testing.T) {
	base := &clientBase{}
	n := dialServer(t, base, serveExec(t, newUpstream()), withCredentials())
	ctx, target := timeout(t), echoTarget(t)
	conn, err := n.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := n.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ network, address string }{{"tcp", target}, {"cmd", "relay x"}, {"udp", "198.51.100.7:53"}} {
		if conn, err := n.DialContext(ctx, d.network, d.address); !errors.Is(err, net.ErrClosed) {
			if conn != nil {
				conn.Close()
			}
			t.Errorf("dial %s after Close = %v, want net.ErrClosed", d.network, err)
		}
	}
	if got := base.dials.Load(); got != 1 {
		t.Fatalf("client dials = %d, want only the first: no reconnect after Close", got)
	}
}
