package netcat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/protocols/command"
)

func TestMain(m *testing.M) {
	if os.Getenv("PERMUTEPROXY_FAKE_NC") != "" {
		os.Exit(fakeNetcat(os.Args[1:]))
	}
	m.Run()
}

// fakeNetcat behaves like Linux netcat-openbsd: stdin EOF is not passed on as a shutdown unless
// -N is given, so the process only exits once the peer closes.
func fakeNetcat(args []string) int {
	var listen, shutdown bool
	var hostPort []string
	for _, arg := range args {
		switch arg {
		case "-l":
			listen = true
		case "-N":
			shutdown = true
		default:
			hostPort = append(hostPort, arg)
		}
	}
	if len(hostPort) != 2 {
		fmt.Fprintln(os.Stderr, "fake nc: want host and port")
		return 2
	}
	address := net.JoinHostPort(hostPort[0], hostPort[1])
	var conn net.Conn
	var err error
	if listen {
		var ln net.Listener
		if ln, err = net.Listen("tcp", address); err == nil {
			conn, err = ln.Accept()
			ln.Close()
		}
	} else {
		conn, err = net.Dial("tcp", address)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake nc:", err)
		return 1
	}
	go func() {
		io.Copy(conn, os.Stdin)
		if shutdown {
			conn.(*net.TCPConn).CloseWrite()
		}
	}()
	io.Copy(os.Stdout, conn)
	return 0
}

// recording is a Runner whose commands go through run and are killed and reaped at the test's end.
func recording(t *testing.T, waitDelay time.Duration, run func(name string, args []string) ([]string, error)) (Runner, func() []net.Conn) {
	t.Helper()
	var mu sync.Mutex
	var started []net.Conn
	// The commands themselves run on a Runner of their own, as a custom Command replaces os/exec.
	inner := &command.Runner{WaitDelay: waitDelay}
	n := Runner{&command.Runner{WaitDelay: waitDelay}}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		argv, err := run(name, args)
		if err != nil {
			return nil, err
		}
		conn, err := inner.DialContext(ctx, "cmd", cmdutils.Quote(argv))
		if err == nil {
			mu.Lock()
			started = append(started, conn)
			mu.Unlock()
		}
		return conn, err
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range started {
			process(t, conn).Kill()
			reaped(t, conn)
		}
	})
	return n, func() []net.Conn {
		mu.Lock()
		defer mu.Unlock()
		return append([]net.Conn(nil), started...)
	}
}

// fakeLinux runs the nc networks through the test binary acting as Linux netcat.
func fakeLinux(t *testing.T, waitDelay time.Duration) Runner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PERMUTEPROXY_FAKE_NC", "1")
	n, _ := recording(t, waitDelay, func(name string, args []string) ([]string, error) {
		if name != "nc" {
			return nil, fmt.Errorf("unexpected command %q", name)
		}
		return append([]string{exe}, args...), nil
	})
	return n
}

// spawning is a Runner recording each command it starts.
func spawning(t *testing.T) (Runner, func() []net.Conn) {
	t.Helper()
	return recording(t, 0, func(name string, args []string) ([]string, error) {
		return append([]string{name}, args...), nil
	})
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("%s needs a POSIX system", name)
	}
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s executable unavailable: %v", name, err)
	}
}

func process(t *testing.T, conn net.Conn) netutils.Process {
	t.Helper()
	p, ok := conn.(netutils.Process)
	if !ok {
		t.Fatal("conn hides its process")
	}
	return p
}

// reaped waits for the command behind conn to be reaped and returns its exit error.
func reaped(t *testing.T, conn net.Conn) error {
	t.Helper()
	p := process(t, conn)
	select {
	case <-p.Done():
		return p.Err()
	case <-time.After(10 * time.Second):
		t.Fatal("command not reaped")
		return nil
	}
}

func signaled(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && !exit.Exited()
}

// socketPath stays under the unix socket path limit, which t.TempDir's test-named paths exceed.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// serve answers each accepted connection's ping with pong and returns Accept's first error.
func serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err == nil {
				conn.Write([]byte("pong"))
			}
		}()
	}
}

func chain(network, address string) permuteproxy.Chain {
	return permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: network, Address: address}}
}

// engineListen listens through a TransportEngine, which asks n for what the network's declaration names.
func engineListen(ctx context.Context, n permuteproxy.Network, network, address string) (net.Listener, error) {
	tr, err := permuteproxy.TransportEngine{Base: n}.Transport(chain(network, address))
	if err != nil {
		return nil, err
	}
	return tr.Listen(ctx)
}

func pingPong(ctx context.Context, n permuteproxy.Network, network, address string) error {
	tr, err := permuteproxy.TransportEngine{Base: n}.Transport(chain(network, address))
	if err != nil {
		return err
	}
	client, err := tr.Dial(ctx, permuteproxy.Stream)
	if err != nil {
		return err
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		return err
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		return err
	}
	if string(buf) != "pong" {
		return fmt.Errorf("read %q, want pong", buf)
	}
	return nil
}

// exchange redials until the listener's nc has bound and answered, or its Accept loop failed.
func exchange(ctx context.Context, n permuteproxy.Network, network, address string, failed <-chan error) error {
	for {
		err := pingPong(ctx, n, network, address)
		if err == nil {
			return nil
		}
		select {
		case aerr := <-failed:
			return fmt.Errorf("Accept: %w (client: %v)", aerr, err)
		case <-ctx.Done():
			return err
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type result struct {
	conn net.Conn
	err  error
}

func acceptAsync(ln net.Listener) <-chan result {
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()
	return ch
}

// answer serves one ping like serve does and hands the closed connection back on conns.
func answer(ln net.Listener, conns chan<- net.Conn) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err == nil {
		conn.Write([]byte("pong"))
	}
	conn.Close()
	conns <- conn
	return nil
}

// waitPath polls for the socket file nc creates, the only readiness signal it gives.
func waitPath(t *testing.T, path string, exists bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); (err == nil) == exists {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: exists=%v did not happen", path, exists)
}

// fakeSpawn stands in for an nc run through a custom Command: the test drives peer and reaps it.
type fakeSpawn struct {
	net.Conn
	peer      net.Conn
	done      chan struct{}
	deadlines chan time.Time
	once      sync.Once
	err       error
}

func (p *fakeSpawn) Done() <-chan struct{} { return p.done }

func (p *fakeSpawn) Err() error { return p.err }

func (p *fakeSpawn) SetReadDeadline(t time.Time) error {
	select {
	case p.deadlines <- t:
	default:
	}
	return p.Conn.SetReadDeadline(t)
}

func (p *fakeSpawn) Kill() error {
	p.peer.Close()
	p.finish(errors.New("signal: killed"))
	return nil
}

// finish reaps the command with err while its output stays open.
func (p *fakeSpawn) finish(err error) {
	p.once.Do(func() {
		p.err = err
		close(p.done)
	})
}

// bindSocket places a live socket at address the way nc -Ul does.
func bindSocket(t *testing.T, address string) {
	t.Helper()
	ln, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
}

// echoes sends msg as one datagram to conn's fixed peer and wants it back from that peer.
func echoes(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("conn is not a net.PacketConn")
	}
	if _, err := pc.WriteTo([]byte(msg), conn.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("ReadFrom = %q, %v; want %q echoed", buf[:n], err, msg)
	}
	if from.String() != conn.RemoteAddr().String() {
		t.Fatalf("datagram from %v, want the fixed peer %v", from, conn.RemoteAddr())
	}
}
