package netcat

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
	"github.com/wzshiming/permuteproxy/protocols/command"
)

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
	n := Runner{&command.Runner{}}
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
	n := Runner{&command.Runner{}}
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

// Once an nc has exited before its first byte, Accept waits for its output for the Runner's WaitDelay.
func TestNetcatUnixExitWindowIsWaitDelay(t *testing.T) {
	const waitDelay = 200 * time.Millisecond
	spawns := make(chan *fakeSpawn, 1)
	n := Runner{&command.Runner{WaitDelay: waitDelay}}
	n.Command = func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		local, peer := net.Pipe()
		p := &fakeSpawn{Conn: local, peer: peer, done: make(chan struct{}), deadlines: make(chan time.Time, 4)}
		spawns <- p
		return p, nil
	}
	ln, err := n.Listen(context.Background(), "cmd-nc-unix", socketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	res := acceptAsync(ln)
	p := <-spawns
	before := time.Now()
	p.finish(nil)
	select {
	case d := <-p.deadlines:
		if window := d.Sub(before); window < waitDelay || window > waitDelay+500*time.Millisecond {
			t.Fatalf("exit deadline %v after exit, want WaitDelay %v", window, waitDelay)
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
}

func TestNetcatRejectsNegativeWaitDelay(t *testing.T) {
	n := Runner{&command.Runner{WaitDelay: -time.Second}}
	for _, network := range []string{"cmd-nc", "cmd-nc-unix"} {
		if _, err := engineListen(context.Background(), n, network, "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "negative WaitDelay") {
			t.Fatalf("Listen %s = %v, want the negative WaitDelay refused", network, err)
		}
	}
}

// A plain command.Runner listens on cmd-nc-unix only as a Runner of this package, which takes no network but those and cmd.
func TestRunnerRefusesOtherNetworks(t *testing.T) {
	ctx := context.Background()
	if _, err := command.Network.Listen(ctx, "cmd-nc-unix", socketPath(t)); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("command.Network.Listen(cmd-nc-unix) = %v, want ErrUnsupported", err)
	}
	if _, err := Network.Listen(ctx, "tcp", "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Network.Listen(tcp) = %v, want ErrUnsupported", err)
	}
}
