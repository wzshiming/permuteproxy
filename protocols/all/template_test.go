//go:build unix

package all_test

import (
	"net/http"
	"net/http/httptest"
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
