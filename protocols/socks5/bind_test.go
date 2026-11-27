package socks5

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

// reach dials ln's address directly and round-trips through the conn ln accepts for it.
func reach(t *testing.T, ln net.Listener) {
	t.Helper()
	peer, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, want := conn.RemoteAddr().String(), peer.LocalAddr().String(); got != want {
		t.Fatalf("RemoteAddr = %s, want the peer's %s", got, want)
	}
	if got, want := conn.LocalAddr().String(), ln.Addr().String(); got != want {
		t.Fatalf("LocalAddr = %s, want the listener's %s", got, want)
	}
	go func() {
		buf := make([]byte, 4)
		if n, err := peer.Read(buf); err == nil {
			peer.Write(buf[:n])
		}
	}()
	testutils.RoundTrip(t, conn, "ping", "ping")
}

func TestListenAcceptsAtTheProxy(t *testing.T) {
	for _, tt := range []struct {
		name    string
		opts    permuteproxy.Options
		resolve bool
	}{
		{"anonymous", nil, true},
		{"authenticated", permuteproxy.Options{"username": "u", "password": "p"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := dialer(t, testutils.System{}, serve(t, testutils.System{}, tt.opts), tt.opts, tt.resolve)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ln, err := n.Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if addr, ok := ln.Addr().(*net.TCPAddr); !ok || addr.Port == 0 || !addr.IP.IsLoopback() {
				t.Fatalf("Addr = %v, want the loopback port the proxy bound", ln.Addr())
			}
			// Each BIND accepts one connection, so later ones show the listener asked again for its address.
			for range 3 {
				reach(t, ln)
			}
			// A slow accept outlasts the proxy's reuse of its listener, and the address is still the same.
			time.Sleep(time.Second)
			reach(t, ln)
		})
	}
}

func TestListenCloseEndsAccept(t *testing.T) {
	n := dialer(t, testutils.System{}, serve(t, testutils.System{}, nil), nil, true)
	ln, err := n.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failed := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		failed <- err
	}()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := testutils.Wait(t, failed, "Accept after Close"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want net.ErrClosed", err)
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want net.ErrClosed", err)
	}
}

func TestListenFailsWhenTheProxyCannotBind(t *testing.T) {
	upstream := permuteproxy.NetworkFuncs{}
	n := dialer(t, testutils.System{}, serve(t, upstream, nil), nil, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ln, err := n.Listen(ctx, "tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("Listen succeeded at a proxy whose upstream cannot listen")
	}
	if _, err := n.Listen(ctx, "tcp", "127.0.0.1:port"); err == nil {
		t.Fatal("Listen succeeded at a port that is not a number")
	}
	if _, err := n.Listen(ctx, "udp", "127.0.0.1:0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Listen udp = %v, want ErrUnsupported", err)
	}
}

func TestListenWithWrongPasswordFails(t *testing.T) {
	addr := serve(t, testutils.System{}, permuteproxy.Options{"username": "u", "password": "p"})
	n := dialer(t, testutils.System{}, addr, permuteproxy.Options{"username": "u", "password": "wrong"}, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ln, err := n.Listen(ctx, "tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("Listen succeeded with a wrong password")
	}
}
