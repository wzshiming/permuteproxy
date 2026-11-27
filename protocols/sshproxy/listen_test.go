package sshproxy

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
)

func TestListenForwardsWhatTheServerAccepts(t *testing.T) {
	for _, tt := range []struct{ network, address string }{
		{"tcp", "127.0.0.1:0"},
		{"unix", filepath.Join(t.TempDir(), "forward.sock")},
	} {
		t.Run(tt.network, func(t *testing.T) {
			addr := serve(t, withCredentials("hostkey_data", hostKey), testutils.System{})
			n := dialServer(t, testutils.System{}, addr, withCredentials())
			ln, err := n.Listen(timeout(t), tt.network, tt.address)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			for range 2 {
				peer, err := net.DialTimeout(tt.network, ln.Addr().String(), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				conn, err := ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				go io.Copy(peer, peer)
				testutils.RoundTrip(t, conn, "ping", "ping")
			}
			// The listener shares the connection dials use.
			target := testutils.ServeEcho(t, listen(t)).String()
			conn, err := n.DialContext(timeout(t), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			testutils.RoundTrip(t, conn, "ping", "ping")
		})
	}
}

func TestListenRefusedKeepsTheConnection(t *testing.T) {
	base := &clientBase{}
	addr := serve(t, withCredentials("hostkey_data", hostKey), permuteproxy.NetworkFuncs{DialContextFunc: testutils.System{}.DialContext})
	n := dialServer(t, base, addr, withCredentials())
	if ln, err := n.Listen(timeout(t), "tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("Listen succeeded at a server whose upstream cannot listen")
	}
	target := testutils.ServeEcho(t, listen(t)).String()
	conn, err := n.DialContext(timeout(t), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	testutils.RoundTrip(t, conn, "ping", "ping")
	if got := base.dials.Load(); got != 1 {
		t.Fatalf("base dials = %d, want the one connection kept", got)
	}
}
