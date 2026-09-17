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
	"testing"
	"time"
)

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("%s needs a POSIX system", name)
	}
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s executable unavailable: %v", name, err)
	}
}

func TestCommandCloseWaitsForExit(t *testing.T) {
	requireCommand(t, "sh")
	mark := filepath.Join(t.TempDir(), "exited")
	conn, err := command(context.Background(), "sh", "-c", `cat >/dev/null; : > "$0"`, mark)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("command still running after Close: %v", err)
	}
}

func TestCommandCancelKillsCommand(t *testing.T) {
	requireCommand(t, "cat")
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := command(ctx, "cat")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v after cancel, want EOF", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
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

func pingPong(ctx context.Context, network, address string) error {
	client, err := Network.DialContext(ctx, network, address)
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
func exchange(ctx context.Context, network, address string, failed <-chan error) error {
	for {
		err := pingPong(ctx, network, address)
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
				if err := exchange(ctx, tt.network, address, failed); err != nil {
					t.Fatalf("connection %d: %v", i, err)
				}
			}
		})
	}
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
		defer ln.Close()
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
			t.Fatal("Accept succeeded on an address another listener holds")
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
		defer ln.Close()
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
			t.Fatal("Accept succeeded on a regular file")
		}
		if got, err := os.ReadFile(address); err != nil || string(got) != "keep" {
			t.Fatalf("file after failed bind: %q, %v", got, err)
		}
	})
}
