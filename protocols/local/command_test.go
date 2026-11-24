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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestMain(m *testing.M) {
	if os.Getenv("PERMUTEPROXY_FAKE_NC") != "" {
		os.Exit(fakeNetcat(os.Args[1:]))
	}
	if os.Getenv("PERMUTEPROXY_FAKE_SOCAT") != "" {
		os.Exit(fakeSocat(os.Args[1:]))
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

// fakeSocat relays like socat - UDP:host:port, one datagram per read of stdin, until stdin ends.
func fakeSocat(args []string) int {
	if len(args) != 3 || args[0] != "socat" || args[1] != "-" || !strings.HasPrefix(args[2], "UDP:") {
		fmt.Fprintln(os.Stderr, "fake socat: want socat - UDP:host:port")
		return 2
	}
	conn, err := net.Dial("udp", strings.TrimPrefix(args[2], "UDP:"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake socat:", err)
		return 1
	}
	go func() {
		io.Copy(conn, os.Stdin)
		conn.Close()
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
	var mu sync.Mutex
	var started []net.Conn
	n := &Local{WaitDelay: waitDelay}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		if name != "nc" {
			return nil, fmt.Errorf("unexpected command %q", name)
		}
		conn, err := n.command(ctx, exe, args...)
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

// waitPIDs polls for the pids a script appends to pidFile and kills those processes when the test ends.
func waitPIDs(t *testing.T, pidFile string, count int) {
	t.Helper()
	var pids []int
	t.Cleanup(func() {
		for _, pid := range pids {
			if p, err := os.FindProcess(pid); err == nil {
				p.Kill()
			}
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(pidFile)
		pids = pids[:0]
		for _, line := range strings.Fields(string(data)) {
			if pid, err := strconv.Atoi(line); err == nil {
				pids = append(pids, pid)
			}
		}
		if len(pids) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: %d pids not written", pidFile, count)
}

// pidPath returns a fresh pid file path without spaces, safe to pass through a cmd address.
func pidPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "pid")
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
			pidFile := pidPath(t)
			n := &Local{WaitDelay: 200 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := n.command(ctx, "sh", "-c", tt.script, pidFile)
			if err != nil {
				t.Fatal(err)
			}
			waitPIDs(t, pidFile, 1)
			if tt.cancel {
				cancel()
			}
			err = reaped(t, conn)
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

// The shell leaves a child holding stdout and exits before any byte: Accept must not hang on it.
func TestListenerFirstByteNotPinnedByDescendant(t *testing.T) {
	requireCommand(t, "sh")
	t.Run("failure", func(t *testing.T) {
		pidFile := pidPath(t)
		n := &Local{WaitDelay: 200 * time.Millisecond}
		ln, err := n.Listen(context.Background(), "cmd", `sh -c 'sleep 30 & echo $! >> "$0"; exit 3' `+pidFile)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		res := acceptAsync(ln)
		waitPIDs(t, pidFile, 1)
		var exit *exec.ExitError
		select {
		case r := <-res:
			if !errors.As(r.err, &exit) || exit.ExitCode() != 3 {
				t.Fatalf("Accept = %v, want exit status 3", r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Accept hung after the shell exited while its child held stdout")
		}
	})
	t.Run("restart", func(t *testing.T) {
		pidFile := pidPath(t)
		stopped := errors.New("enough")
		var spawns int
		n := &Local{WaitDelay: 200 * time.Millisecond}
		n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
			if spawns++; spawns > 2 {
				return nil, stopped
			}
			return n.command(ctx, name, args...)
		}
		ln, err := n.Listen(context.Background(), "cmd", `sh -c 'sleep 30 & echo $! >> "$0"' `+pidFile)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		res := acceptAsync(ln)
		defer waitPIDs(t, pidFile, 2)
		select {
		case r := <-res:
			if !errors.Is(r.err, stopped) {
				t.Fatalf("Accept = %v, want %v after two clean exits", r.err, stopped)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Accept hung instead of starting over after a clean exit")
		}
	})
}

func TestListenerDeliversOutputOfShortLivedCommand(t *testing.T) {
	requireCommand(t, "sh")
	ln, err := Network.Listen(context.Background(), "cmd", "sh -c 'echo hi'")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for i := 0; i < 10; i++ {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept %d = %v", i, err)
		}
		got, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || string(got) != "hi\n" {
			t.Fatalf("Accept %d read %q, %v", i, got, err)
		}
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
	if _, err := n.DialContext(context.Background(), "cmd", "cat"); !errors.Is(err, errNegativeWaitDelay) {
		t.Fatalf("DialContext = %v, want %v", err, errNegativeWaitDelay)
	}
	for _, network := range []string{"cmd", "cmd-nc", "cmd-nc-unix"} {
		if _, err := engineListen(context.Background(), n, network, "127.0.0.1:1"); !errors.Is(err, errNegativeWaitDelay) {
			t.Fatalf("Listen %s = %v, want %v", network, err, errNegativeWaitDelay)
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

// engineListen listens through the Engine, which asks n for what the network's declaration names.
func engineListen(ctx context.Context, n *Local, network, address string) (net.Listener, error) {
	tr, err := permuteproxy.Engine{Base: n}.Transport(chain(network, address))
	if err != nil {
		return nil, err
	}
	return tr.Listen(ctx)
}

func pingPong(ctx context.Context, n *Local, network, address string) error {
	tr, err := permuteproxy.Engine{Base: n}.Transport(chain(network, address))
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
		{"cmd-nc", func(t *testing.T) string { return testutils.ReservePort(t) }},
		{"cmd-nc-unix", socketPath},
	} {
		t.Run(tt.network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			address := tt.address(t)
			ln, err := engineListen(ctx, Network, tt.network, address)
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
	address := testutils.ReservePort(t)
	ln, err := engineListen(ctx, n, "cmd-nc", address)
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

func TestNetcatUnixKeepsUnclaimedPendingSocket(t *testing.T) {
	requireCommand(t, "nc")
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
	// No peer ever reached this nc, so nothing proves the file is its socket: it stays.
	if fi, err := os.Lstat(address); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unclaimed socket after Close: %v, %v", fi, err)
	}
}

func TestNetcatUnixRemovesOwnedSocket(t *testing.T) {
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
	// Linux netcat-openbsd ignores stdin EOF, so there it ends only through the kill after WaitDelay.
	if err := reaped(t, <-conns); err != nil && !signaled(err) {
		t.Fatalf("nc ended with %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	waitPath(t, address, false)
}

// Whatever replaces the socket of an idle pending nc must survive the listener's Close.
func TestNetcatUnixKeepsSwappedPendingPath(t *testing.T) {
	requireCommand(t, "nc")
	t.Run("live listener", func(t *testing.T) {
		address := socketPath(t)
		ln, err := Network.Listen(context.Background(), "cmd-nc-unix", address)
		if err != nil {
			t.Fatal(err)
		}
		res := acceptAsync(ln)
		waitPath(t, address, true)
		os.Remove(address)
		foreign, err := net.Listen("unix", address)
		if err != nil {
			t.Fatal(err)
		}
		defer foreign.Close()
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-res:
		case <-time.After(10 * time.Second):
			t.Fatal("Accept did not return after Close")
		}
		conn, err := net.Dial("unix", address)
		if err != nil {
			t.Fatalf("foreign listener unreachable after Close: %v", err)
		}
		conn.Close()
	})
	t.Run("regular file", func(t *testing.T) {
		address := socketPath(t)
		ln, err := Network.Listen(context.Background(), "cmd-nc-unix", address)
		if err != nil {
			t.Fatal(err)
		}
		res := acceptAsync(ln)
		waitPath(t, address, true)
		os.Remove(address)
		if err := os.WriteFile(address, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-res:
		case <-time.After(10 * time.Second):
			t.Fatal("Accept did not return after Close")
		}
		if got, err := os.ReadFile(address); err != nil || string(got) != "keep" {
			t.Fatalf("file after Close: %q, %v", got, err)
		}
	})
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
func (p *fakeSpawn) Err() error            { return p.err }

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

// Once a command has exited before its first byte, Accept waits for its output for the resolved WaitDelay.
func TestListenerExitWindowIsWaitDelay(t *testing.T) {
	for _, tt := range []struct {
		name      string
		network   string
		waitDelay time.Duration
		want      time.Duration
	}{
		{"configured", "cmd", 200 * time.Millisecond, 200 * time.Millisecond},
		{"default", "cmd", 0, defaultWaitDelay},
		{"nc unix", "cmd-nc-unix", 200 * time.Millisecond, 200 * time.Millisecond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spawns := make(chan *fakeSpawn, 1)
			n := &Local{WaitDelay: tt.waitDelay}
			n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
				local, peer := net.Pipe()
				p := &fakeSpawn{Conn: local, peer: peer, done: make(chan struct{}), deadlines: make(chan time.Time, 4)}
				spawns <- p
				return p, nil
			}
			address := "fake"
			if tt.network == "cmd-nc-unix" {
				address = socketPath(t)
			}
			ln, err := n.Listen(context.Background(), tt.network, address)
			if err != nil {
				t.Fatal(err)
			}
			res := acceptAsync(ln)
			p := <-spawns
			before := time.Now()
			p.finish(nil)
			select {
			case d := <-p.deadlines:
				if window := d.Sub(before); window < tt.want || window > tt.want+500*time.Millisecond {
					t.Fatalf("exit deadline %v after exit, want WaitDelay %v", window, tt.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no read deadline set after the command exited")
			}
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-res:
				if !errors.Is(r.err, net.ErrClosed) {
					t.Fatalf("Accept = %v, want net.ErrClosed", r.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Accept did not return after Close")
			}
		})
	}
}

func TestNetcatUnixClaimAgainstExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	newSpawn := func() *fakeSpawn {
		local, peer := net.Pipe()
		return &fakeSpawn{Conn: local, peer: peer, done: make(chan struct{})}
	}
	t.Run("claim then exit removes", func(t *testing.T) {
		address := socketPath(t)
		bindSocket(t, address)
		p := newSpawn()
		conn := (&socketFile{path: address}).track(p)
		go p.peer.Write([]byte{1})
		if _, err := conn.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		p.finish(nil)
		waitPath(t, address, false)
	})
	t.Run("exit then claim keeps", func(t *testing.T) {
		address := socketPath(t)
		bindSocket(t, address)
		p := newSpawn()
		socket := &socketFile{path: address}
		conn := socket.track(p)
		p.finish(nil)
		socket.before()
		go p.peer.Write([]byte{1})
		if _, err := conn.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		socket.before()
		if _, err := os.Lstat(address); err != nil {
			t.Fatalf("socket removed on a claim made after nc had exited: %v", err)
		}
	})
}

func TestNetcatUnixCustomCommandWithoutProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	address := socketPath(t)
	peers := make(chan net.Conn, 1)
	n := &Local{}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		local, peer := net.Pipe()
		peers <- peer
		return local, nil
	}
	ln, err := n.Listen(context.Background(), "cmd-nc-unix", address)
	if err != nil {
		t.Fatal(err)
	}
	res := acceptAsync(ln)
	peer := <-peers
	// Bound once the command runs, as nc does: the listener refuses a path already taken.
	bindSocket(t, address)
	go peer.Write([]byte("ping"))
	r := <-res
	if r.err != nil {
		t.Fatal(r.err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	go peer.Write([]byte("more"))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r.conn, buf); err != nil || string(buf) != "pingmore" {
		t.Fatalf("read %q, %v after listener Close", buf, err)
	}
	if _, err := os.Lstat(address); err != nil {
		t.Fatalf("socket removed while its connection was open: %v", err)
	}
	if err := r.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(address); !os.IsNotExist(err) {
		t.Fatalf("socket of a closed connection without a process left behind: %v", err)
	}
}

func TestNetcatUnixListenQuotesThePath(t *testing.T) {
	address := filepath.Join(t.TempDir(), "a b.sock")
	argv := make(chan []string, 1)
	n := &Local{}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		argv <- append([]string{name}, args...)
		local, _ := net.Pipe()
		return local, nil
	}
	ln, err := n.Listen(context.Background(), "cmd-nc-unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ln.Accept()
	if got, want := <-argv, []string{"nc", "-Ul", address}; !slices.Equal(got, want) {
		t.Fatalf("listening runs %q, want %q", got, want)
	}
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
	// Settling trails the exit, and a replacement made before it can reuse the inode it compares on ext4.
	waitPath(t, address, false)
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
