package permuteproxy_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/wzshiming/permuteproxy/protocols/httpproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local"
	_ "github.com/wzshiming/permuteproxy/protocols/shadowsocks"
	_ "github.com/wzshiming/permuteproxy/protocols/snappy"
	_ "github.com/wzshiming/permuteproxy/protocols/socks4"
	_ "github.com/wzshiming/permuteproxy/protocols/socks5"
	_ "github.com/wzshiming/permuteproxy/protocols/sshproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/tls"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

func TestTCPListenAndDial(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
	uri := "tcp://127.0.0.1:45678"
	listenConn, _, err := permuteproxy.NewListenConfig(nil, uri)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := listenConn.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			go io.Copy(conn, conn)
		}
	}()

	_, dialConn, err := permuteproxy.NewDialer(nil, uri)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialConn.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	testMsg := []byte("hello")
	reply := make([]byte, 1024)
	_, err = conn.Write(testMsg)
	if err != nil {
		t.Fatal(err)
	}

	n, err := conn.Read(reply)
	if err != nil {
		t.Fatal(err)
	}

	if string(reply[:n]) != string(testMsg) {
		t.Fatal("reply not match")
	}

	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestProxy(t *testing.T) {
	testdata := []string{
		"http://127.0.0.1:45678",
		"http+unix://./test.socs",
		"socks5://127.0.0.1:45678",
		"socks5+unix://./test.socs",
		"socks4://127.0.0.1:45678",
		"socks4+unix://./test.socs",
		"ssh://127.0.0.1:45678",
		"ssh+unix://./test.socs",
		"ss://127.0.0.1:45678",
		"ss+unix://./test.socs",
		"http+snappy://127.0.0.1:45678",
		"http+snappy+unix://./test.socs",
		"socks5+snappy://127.0.0.1:45678",
		"socks5+snappy+unix://./test.socs",
		"socks4+snappy://127.0.0.1:45678",
		"socks4+snappy+unix://./test.socs",
		"ssh+snappy://127.0.0.1:45678",
		"ssh+snappy+unix://./test.socs",
		"ss+snappy://127.0.0.1:45678",
		"ss+snappy+unix://./test.socs",
		"https://127.0.0.1:45678?tls_skip_verify=true&tls_self_signed=true",
		"http+tls://127.0.0.1:45678?tls_skip_verify=true&tls_self_signed=true",
	}
	for _, uri := range testdata {
		t.Run(uri, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.Cleanup(cancel)
			_, runner, err := permuteproxy.NewListenConfig(nil, uri)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				err := runner.Run(ctx)
				if err != nil && !netutils.IsClosedConnError(err) {
					t.Fatal(err)
				}
			}()
			t.Cleanup(func() {
				runner.Close()
			})
			time.Sleep(1 * time.Second)

			dialer, _, err := permuteproxy.NewDialer(nil, uri)
			if err != nil {
				t.Fatal(err)
			}

			want := "OK"
			testserver := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.Write([]byte(want))
			}))
			t.Cleanup(func() {
				testserver.Close()
			})
			cli := testserver.Client()
			cli.Transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
			}

			resp, err := cli.Get(testserver.URL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				resp.Body.Close()
			})
			body, _ := io.ReadAll(resp.Body)
			if want != string(body) {
				t.Fatalf("got %q, want %q", body, want)
			}
		})
	}
}
