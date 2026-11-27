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

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

func TestMain(m *testing.M) {
	if os.Getenv("PERMUTEPROXY_FAKE_SOCAT") != "" {
		os.Exit(fakeSocat(os.Args[1:]))
	}
	m.Run()
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
	if _, err := engineListen(context.Background(), n, "cmd", "cat"); !errors.Is(err, errNegativeWaitDelay) {
		t.Fatalf("Listen = %v, want %v", err, errNegativeWaitDelay)
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

func chain(network, address string) permuteproxy.Chain {
	return permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: network, Address: address}}
}

// engineListen listens through a TransportEngine, which asks n for what the network's declaration names.
func engineListen(ctx context.Context, n *Local, network, address string) (net.Listener, error) {
	tr, err := permuteproxy.TransportEngine{Base: n}.Transport(chain(network, address))
	if err != nil {
		return nil, err
	}
	return tr.Listen(ctx)
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

// fakeSpawn stands in for a command run through a custom Command: the test drives peer and reaps it.
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
			ln, err := n.Listen(context.Background(), tt.network, "fake")
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
