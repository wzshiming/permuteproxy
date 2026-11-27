package command

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/wzshiming/permuteproxy"
)

// relayBase answers each cmd dial with a relay echoing the command line dialed.
var relayBase = permuteproxy.NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
	if network != "cmd" {
		return nil, permuteproxy.ErrUnsupported
	}
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		buf := make([]byte, 64)
		for {
			n, err := far.Read(buf)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(far, "%s|%s", address, buf[:n]); err != nil {
				return
			}
		}
	}()
	return near, nil
}}

func relayExchange(t *testing.T, conn net.Conn) string {
	t.Helper()
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestTemplateClientFillsTheTarget(t *testing.T) {
	for _, tt := range []struct {
		uri, network, target, want string
	}{
		{"cmd:ssh -W %h:%p jump", "tcp", "example.com:443", "ssh -W example.com:443 jump|x"},
		{"command:ssh -W %h:%p jump", "tcp", "example.com:443", "ssh -W example.com:443 jump|x"},
		{"cmd:ssh -W %h:%p jump", "tcp6", "[::1]:22", "ssh -W ::1:22 jump|x"},
		{"cmd:printf 100%% %h", "tcp", "host:1", "printf 100% host|x"},
		{"cmd:ssh jump", "tcp", "host:1", "ssh jump|x"},
		{"cmd:sh -c 'nc %h %p'", "tcp", "host:1", "sh -c 'nc host 1'|x"},
		{"cmd:nc $(echo %h) \"%p\"", "tcp", "host:1", "nc $(echo host) \"1\"|x"},
		{"cmd:relay %n %h %p", "tcp4", "127.0.0.1:1", "relay tcp4 127.0.0.1 1|x"},
		{"cmd:nc -U %h", "unix", "./run/proxy.sock", "nc -U ./run/proxy.sock|x"},
		{"cmd:relay %n '%h' [%p]", "unix", "/tmp/x", "relay unix '/tmp/x' []|x"},
	} {
		c, err := permuteproxy.ParseURI(tt.uri)
		if err != nil {
			t.Fatalf("%s: %v", tt.uri, err)
		}
		n, err := permuteproxy.ClientEngine{Base: relayBase}.Client(c)
		if err != nil {
			t.Fatalf("%s: %v", tt.uri, err)
		}
		conn, err := n.DialContext(context.Background(), tt.network, tt.target)
		if err != nil {
			t.Fatalf("%s: dial %s: %v", tt.uri, tt.target, err)
		}
		if got := relayExchange(t, conn); got != tt.want {
			t.Errorf("%s: dial %s ran %q, want %q", tt.uri, tt.target, got, tt.want)
		}
	}
}

func TestTemplateClientRefuses(t *testing.T) {
	for _, tt := range []struct {
		uri  string
		want string
	}{
		{"cmd:nc %x", `placeholder "%x"`},
		{"cmd:nc %a", `placeholder "%a"`},
		{"cmd:nc %h %", `placeholder "%"`},
	} {
		c, err := permuteproxy.ParseURI(tt.uri)
		if err != nil {
			t.Fatalf("%s: %v", tt.uri, err)
		}
		_, err = permuteproxy.ClientEngine{Base: relayBase}.Client(c)
		if !errors.Is(err, permuteproxy.ErrInvalidChain) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want permuteproxy.ErrInvalidChain with %q", tt.uri, err, tt.want)
		}
	}

	n, err := permuteproxy.ClientEngine{Base: relayBase}.Client(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd", Address: "nc %h %p"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tt := range [][2]string{
		{"tcp", "-oProxyCommand=x:1"}, {"tcp", "a;b:1"}, {"tcp", "host:port"}, {"tcp", "host"},
		{"unix", ""}, {"unix", "-x"}, {"unix", "/tmp/a b"}, {"unix", "/tmp/a;b"}, {"unix", "/tmp/a'b"}, {"unix", "/tmp/$(b)"},
	} {
		if conn, err := n.DialContext(ctx, tt[0], tt[1]); err == nil {
			conn.Close()
			t.Errorf("dial %s %q succeeded", tt[0], tt[1])
		}
		if ln, err := n.Listen(ctx, tt[0], tt[1]); err == nil {
			ln.Close()
			t.Errorf("listen %s %q succeeded", tt[0], tt[1])
		}
	}
	if _, err := n.DialContext(ctx, "udp", "host:1"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("udp over a stream command: %v, want permuteproxy.ErrUnsupported", err)
	}
	if _, err := n.DialContext(ctx, "unixgram", "/tmp/x"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("unixgram target: %v, want permuteproxy.ErrUnsupported", err)
	}
	if _, err := n.Listen(ctx, "udp", ":0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("listen udp: %v, want permuteproxy.ErrUnsupported", err)
	}
	if _, err := n.Listen(ctx, "tcp", ":0"); !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Errorf("listen over a base without Listen: %v, want permuteproxy.ErrUnsupported", err)
	}
}

func TestTemplateClientListens(t *testing.T) {
	var listened []string
	base := permuteproxy.NetworkFuncs{ListenFunc: func(_ context.Context, network, address string) (net.Listener, error) {
		listened = append(listened, network+" "+address)
		return nil, errors.New("recorded")
	}}
	n, err := permuteproxy.ClientEngine{Base: base}.Client(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd", Address: "sh -c 'nc -l %h %p' %n"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	n.Listen(ctx, "tcp", ":8080")
	n.Listen(ctx, "tcp6", "[::1]:8080")
	n.Listen(ctx, "unix", "/run/x.sock")
	want := []string{"cmd sh -c 'nc -l  8080' tcp", "cmd sh -c 'nc -l ::1 8080' tcp6", "cmd sh -c 'nc -l /run/x.sock ' unix"}
	if strings.Join(listened, "\n") != strings.Join(want, "\n") {
		t.Errorf("listened %q, want %q", listened, want)
	}
}
