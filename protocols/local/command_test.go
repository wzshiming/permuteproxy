package local

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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

// fakeLinux runs the nc schemes through the test binary acting as Linux netcat.
func fakeLinux(t *testing.T, waitDelay time.Duration) *Local {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PERMUTEPROXY_FAKE_NC", "1")
	n := &Local{WaitDelay: waitDelay}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		if name != "nc" {
			return nil, fmt.Errorf("unexpected command %q", name)
		}
		return n.command(ctx, exe, args...)
	}
	return n
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

func process(t *testing.T, conn net.Conn) Process {
	t.Helper()
	p, ok := conn.(Process)
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

func TestCommandCloseReturnsBeforeExit(t *testing.T) {
	requireCommand(t, "sleep")
	n := &Local{WaitDelay: 200 * time.Millisecond}
	conn, err := n.command(context.Background(), "sleep", "30")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process(t, conn).Done():
		t.Fatal("Close waited for the command to exit")
	default:
	}
	if err := reaped(t, conn); !signaled(err) {
		t.Fatalf("command ignoring EOF ended with %v, want a kill after WaitDelay", err)
	}
}

func TestCommandCloseIsIdempotent(t *testing.T) {
	requireCommand(t, "cat")
	conn, err := Network.command(context.Background(), "cat")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := reaped(t, conn); err != nil {
		t.Fatalf("cat ended with %v after EOF", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close after exit = %v", err)
	}
	if err := process(t, conn).Kill(); err != nil {
		t.Fatalf("Kill after exit = %v", err)
	}
}

func TestCommandCloseDrainsOutput(t *testing.T) {
	requireCommand(t, "sh")
	n := &Local{WaitDelay: 30 * time.Second}
	conn, err := n.command(context.Background(), "sh", "-c", "cat >/dev/null; head -c 1000000 /dev/zero")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reaped(t, conn); err != nil {
		t.Fatalf("command blocked on its output after Close: %v", err)
	}
}

func TestCommandOutputSurvivesExit(t *testing.T) {
	requireCommand(t, "sh")
	conn, err := Network.command(context.Background(), "sh", "-c", "head -c 4096 /dev/zero")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := reaped(t, conn); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || len(got) != 4096 {
		t.Fatalf("read %d bytes, %v after exit, want 4096", len(got), err)
	}
}

func TestCommandClosedStdoutKeepsStdin(t *testing.T) {
	requireCommand(t, "sh")
	mark := filepath.Join(t.TempDir(), "exited")
	conn, err := Network.command(context.Background(), "sh", "-c", `exec >&-; cat >/dev/null; : > "$0"`, mark)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v, want EOF once the command closed its stdout", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write after stdout EOF = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reaped(t, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("command did not read stdin to its end: %v", err)
	}
}

// killPID ends the descendant a test left behind.
func killPID(t *testing.T, pidFile string) {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := os.FindProcess(pid); err == nil {
		p.Kill()
	}
}

func TestCommandDoneNotPinnedByDescendant(t *testing.T) {
	requireCommand(t, "sh")
	for name, tt := range map[string]struct {
		script string
		cancel bool
	}{
		"exit":   {`sleep 30 & echo $! > "$0"`, false},
		"cancel": {`sleep 30 & echo $! > "$0"; wait`, true},
	} {
		t.Run(name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "pid")
			n := &Local{WaitDelay: 200 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := n.command(ctx, "sh", "-c", tt.script, pidFile)
			if err != nil {
				t.Fatal(err)
			}
			if tt.cancel {
				cancel()
			}
			err = reaped(t, conn)
			defer killPID(t, pidFile)
			if tt.cancel && !signaled(err) {
				t.Fatalf("shell ended with %v after cancel, want a kill while its child held stdout", err)
			}
			if !tt.cancel && err != nil {
				t.Fatalf("shell ended with %v while its child held stdout", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("Read succeeded after Close")
			}
		})
	}
}

func TestCommandUnexpectedExit(t *testing.T) {
	requireCommand(t, "sh")
	conn, err := Network.command(context.Background(), "sh", "-c", "exit 3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v, want EOF", err)
	}
	var exit *exec.ExitError
	if err := reaped(t, conn); !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("Err() = %v, want exit status 3", err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("Write succeeded after the command exited")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCommandKill(t *testing.T) {
	requireCommand(t, "sleep")
	conn, err := Network.command(context.Background(), "sleep", "30")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := process(t, conn).Kill(); err != nil {
		t.Fatal(err)
	}
	if err := reaped(t, conn); !signaled(err) {
		t.Fatalf("Err() = %v after Kill, want a signal", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v after Kill, want EOF", err)
	}
}

func TestCommandCancelKillsAfterWaitDelay(t *testing.T) {
	requireCommand(t, "cat")
	n := &Local{WaitDelay: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := n.command(ctx, "cat")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if err := reaped(t, conn); !signaled(err) {
		t.Fatalf("cat ended with %v after cancel, want a kill", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v after cancel, want EOF", err)
	}
}

func TestCommandRejectsNegativeWaitDelay(t *testing.T) {
	n := &Local{WaitDelay: -time.Second}
	if _, err := n.DialContext(context.Background(), "cmd", "cat"); err == nil {
		t.Fatal("DialContext accepted a negative WaitDelay")
	}
	for _, network := range []string{"cmd", "cmd-nc", "cmd-nc-unix"} {
		if _, err := n.Listen(context.Background(), network, "127.0.0.1:1"); err == nil {
			t.Fatalf("Listen %s accepted a negative WaitDelay", network)
		}
	}
}

func TestDialSurvivesContextCancel(t *testing.T) {
	requireCommand(t, "cat")
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := Network.DialContext(ctx, "cmd", "cat")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("read %q, %v after the dial context was canceled", buf, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reaped(t, conn); err != nil {
		t.Fatalf("cat ended with %v after EOF", err)
	}
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

func pingPong(ctx context.Context, n *Local, network, address string) error {
	client, err := n.DialContext(ctx, network, address)
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
func exchange(ctx context.Context, n *Local, network, address string, failed <-chan error) error {
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

func TestNetcatSequentialConnections(t *testing.T) {
	requireCommand(t, "nc")
	for _, tt := range []struct {
		network string
		address func(t *testing.T) string
	}{
		{"cmd-nc", reservePort},
		{"cmd-nc-unix", socketPath},
	} {
		t.Run(tt.network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			address := tt.address(t)
			ln, err := Network.Listen(ctx, tt.network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			failed := make(chan error, 1)
			go func() { failed <- serve(ln) }()
			for i := 0; i < 3; i++ {
				if err := exchange(ctx, Network, tt.network, address, failed); err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
			}
		})
	}
}

func TestFakeLinuxNetcatSequentialConnections(t *testing.T) {
	const waitDelay = 500 * time.Millisecond
	n := fakeLinux(t, waitDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	address := reservePort(t)
	ln, err := n.Listen(ctx, "cmd-nc", address)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	failed := make(chan error, 1)
	go func() { failed <- serve(ln) }()
	for i := 0; i < 3; i++ {
		start := time.Now()
		if err := exchange(ctx, n, "cmd-nc", address, failed); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		if took := time.Since(start); took > waitDelay+5*time.Second {
			t.Fatalf("connection %d took %v, want the previous nc killed within WaitDelay %v", i, took, waitDelay)
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

func TestNetcatUnixRemovesOwnedSocket(t *testing.T) {
	requireCommand(t, "nc")
	t.Run("pending", func(t *testing.T) {
		address := socketPath(t)
		ln, err := Network.Listen(context.Background(), "cmd-nc-unix", address)
		if err != nil {
			t.Fatal(err)
		}
		res := acceptAsync(ln)
		waitPath(t, address, true)
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-res:
			if !errors.Is(r.err, net.ErrClosed) {
				t.Fatalf("Accept = %v, want net.ErrClosed", r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Accept did not return after Close")
		}
		if _, err := os.Lstat(address); !os.IsNotExist(err) {
			t.Fatalf("socket of the killed nc left behind: %v", err)
		}
	})
	t.Run("accepted", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		address := socketPath(t)
		ln, err := Network.Listen(ctx, "cmd-nc-unix", address)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		failed, conns := make(chan error, 1), make(chan net.Conn, 1)
		go func() { failed <- answer(ln, conns) }()
		if err := exchange(ctx, Network, "cmd-nc-unix", address, failed); err != nil {
			t.Fatal(err)
		}
		if err := reaped(t, <-conns); err != nil {
			t.Fatalf("nc ended with %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		waitPath(t, address, false)
	})
}

func TestNetcatUnixKeepsReplacedSocket(t *testing.T) {
	requireCommand(t, "nc")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	address := socketPath(t)
	ln, err := Network.Listen(ctx, "cmd-nc-unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	failed, conns := make(chan error, 1), make(chan net.Conn, 1)
	go func() { failed <- answer(ln, conns) }()
	if err := exchange(ctx, Network, "cmd-nc-unix", address, failed); err != nil {
		t.Fatal(err)
	}
	reaped(t, <-conns)
	os.Remove(address)
	foreign, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if conn, err := ln.Accept(); err == nil {
		conn.Close()
		t.Fatal("Accept succeeded although a foreign socket replaced ours")
	}
	conn, err := net.Dial("unix", address)
	if err != nil {
		t.Fatalf("foreign listener unreachable: %v", err)
	}
	conn.Close()
}

func TestNetcatUnixKeepsForeignPath(t *testing.T) {
	requireCommand(t, "nc")
	t.Run("live listener", func(t *testing.T) {
		address := socketPath(t)
		foreign, err := net.Listen("unix", address)
		if err != nil {
			t.Fatal(err)
		}
		defer foreign.Close()
		ln, err := Network.Listen(context.Background(), "cmd-nc-unix", address)
		if err != nil {
			t.Fatal(err)
		}
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
			t.Fatal("Accept succeeded on an address another listener holds")
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("unix", address)
		if err != nil {
			t.Fatalf("foreign listener unreachable: %v", err)
		}
		conn.Close()
	})
	t.Run("regular file", func(t *testing.T) {
		address := socketPath(t)
		if err := os.WriteFile(address, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		ln, err := Network.Listen(context.Background(), "cmd-nc-unix", address)
		if err != nil {
			t.Fatal(err)
		}
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
			t.Fatal("Accept succeeded on a regular file")
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(address); err != nil || string(got) != "keep" {
			t.Fatalf("file after failed bind: %q, %v", got, err)
		}
	})
}
