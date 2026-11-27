//go:build unix

package all_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"time"

	"context"
	"github.com/wzshiming/permuteproxy/protocols/local"
	"io"
	"testing"

	"github.com/wzshiming/permuteproxy"
)

func TestCommandTemplateClient(t *testing.T) {
	c, err := permuteproxy.ParseURI("cmd:echo %h %p")
	if err != nil {
		t.Fatal(err)
	}
	n, err := permuteproxy.ClientEngine{}.Client(c)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := n.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "example.com 443\n" {
		t.Errorf("command wrote %q", out)
	}
}

// TestCommandTemplateQuoted fills placeholders inside the quotes of a line sh parses again.
func TestCommandTemplateQuoted(t *testing.T) {
	n, err := permuteproxy.NewClient(`cmd:sh -c 'echo %n "%h" %p'`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range [][3]string{
		{"tcp4", "example.com:443", "tcp4 example.com 443\n"},
		{"unix", "./proxy.sock", "unix ./proxy.sock\n"},
	} {
		conn, err := n.DialContext(context.Background(), tt[0], tt[1])
		if err != nil {
			t.Fatal(err)
		}
		out, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || string(out) != tt[2] {
			t.Errorf("dial %s %s wrote %q, %v, want %q", tt[0], tt[1], out, err, tt[2])
		}
	}
}

// TestCommandTemplateListens accepts through nc at a tcp address and at a unix socket.
func TestCommandTemplateListens(t *testing.T) {
	requireNetcat(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := probe.Addr().String()
	probe.Close()
	for _, tt := range [][3]string{
		{"cmd:nc -l %h %p", "tcp", tcpAddr},
		{"cmd:sh -c 'exec nc -Ul %h'", "unix", filepath.Join(t.TempDir(), "x.sock")},
	} {
		t.Run(tt[1], func(t *testing.T) {
			n, err := permuteproxy.NewClient(tt[0])
			if err != nil {
				t.Fatal(err)
			}
			ln, err := n.Listen(context.Background(), tt[1], tt[2])
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				// nc binds some time after Accept started it.
				for i := 0; i < 100; i++ {
					conn, err := net.Dial(tt[1], tt[2])
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
			defer conn.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("accepted conn read %q, %v", buf, err)
			}
		})
	}
}

// TestCommandTemplateChains puts a command template under a socks5 hop and over an ssh hop.
func TestCommandTemplateChains(t *testing.T) {
	requireNetcat(t)
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("OK"))
	}))
	t.Cleanup(target.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nc := parse(t, "cmd:nc %h %p")

	t.Run("socks5 over template", func(t *testing.T) {
		base := newProbe(local.Network)
		_, done := start(t, permuteproxy.ServerEngine{Base: base}, parse(t, "socks5://127.0.0.1:0"))
		addr := waitBound(t, base, done)
		hop1, err := permuteproxy.ClientEngine{}.Client(nc)
		if err != nil {
			t.Fatal(err)
		}
		hop2, err := permuteproxy.ClientEngine{Base: hop1}.Client(parse(t, "socks5://"+addr.String()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeIf(hop2) })
		if got, err := fetch(ctx, hop2, target.URL); err != nil || got != "OK" {
			t.Fatalf("fetch = %q, %v", got, err)
		}
	})

	t.Run("template over ssh", func(t *testing.T) {
		hop2, err := permuteproxy.ClientEngine{Base: sshExec(t, local.Network)}.Client(nc)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := fetch(ctx, hop2, target.URL); err != nil || got != "OK" {
			t.Fatalf("fetch = %q, %v", got, err)
		}
	})
}
