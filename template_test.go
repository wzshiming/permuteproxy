package permuteproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// relayBase answers each cmd dial with a relay echoing the command line dialed.
var relayBase = NetworkFuncs{DialContextFunc: func(_ context.Context, network, address string) (net.Conn, error) {
	if network != "cmd" {
		return nil, ErrUnsupported
	}
	return newRelay(address), nil
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
		{"cmd:ssh -W %h:%p jump", "tcp6", "[::1]:22", "ssh -W ::1:22 jump|x"},
		{"cmd:printf 100%% %h", "tcp", "host:1", "printf 100% host|x"},
		{"cmd:ssh jump", "tcp", "host:1", "ssh jump|x"},
	} {
		c, err := ParseURI(tt.uri)
		if err != nil {
			t.Fatalf("%s: %v", tt.uri, err)
		}
		n, err := ClientEngine{Base: relayBase}.Client(c)
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
		{"cmd:sh -c 'nc %h %p'", "inside quotes"},
		{"cmd:nc $(echo %h)", "follows"},
	} {
		c, err := ParseURI(tt.uri)
		if err != nil {
			t.Fatalf("%s: %v", tt.uri, err)
		}
		_, err = ClientEngine{Base: relayBase}.Client(c)
		if !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want ErrInvalidChain with %q", tt.uri, err, tt.want)
		}
	}

	n, err := ClientEngine{Base: relayBase}.Client(Chain{Endpoint: Endpoint{Network: "cmd", Address: "nc %h %p"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, target := range []string{"-oProxyCommand=x:1", "a;b:1", "host:port", "host"} {
		if conn, err := n.DialContext(ctx, "tcp", target); err == nil {
			conn.Close()
			t.Errorf("dial %q succeeded", target)
		}
	}
	if _, err := n.DialContext(ctx, "udp", "host:1"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("udp over a stream command: %v, want ErrUnsupported", err)
	}
	if _, err := n.DialContext(ctx, "unix", "/tmp/x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unix target: %v, want ErrUnsupported", err)
	}
	if _, err := n.Listen(ctx, "tcp", ":0"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("listen: %v, want ErrUnsupported", err)
	}
}
