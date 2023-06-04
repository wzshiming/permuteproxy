package permuteproxy_test

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/wzshiming/permuteproxy/protocols/anyproxy"
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

var proxy = permuteproxy.Proxy{}

func TestTCPListenAndDial(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
	uri := "tcp://127.0.0.1:45678"
	listenConn, err := proxy.NewListenConn(uri)
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

	dialConn, err := proxy.NewDialConn(uri)
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
		"socks5+cmd-nc://127.0.0.1:45670",
		"socks5+cmd-nc://u:p@127.0.0.1:45671",
		"socks5+cmd-nc-unix://./test1.socks",
		"socks5+cmd-nc-unix://u:p@./test2.socks",
		"any://127.0.0.1:45678",
		"any://u:p@127.0.0.1:45678",
		"any+unix://./test.socks",
		"any+unix://u:p@./test.socks",
		"http://127.0.0.1:45678",
		"http://u:p@127.0.0.1:45678",
		"http+unix://./test.socks",
		"http+unix://u:p@./test.socks",
		"socks5://127.0.0.1:45678",
		"socks5://u:p@127.0.0.1:45678",
		"socks5+unix://./test.socks",
		"socks5+unix://u:p@./test.socks",
		"socks4://127.0.0.1:45678",
		"socks4://u:p@127.0.0.1:45678",
		"socks4+unix://./test.socks",
		"socks4+unix://u:p@./test.socks",
		"ssh://127.0.0.1:45678",
		"ssh://u:p@127.0.0.1:45678",
		"ssh+unix://./test.socks",
		"ssh+unix://u:p@./test.socks",
		"ss://127.0.0.1:45678",
		"ss://aes-256-gcm:p@127.0.0.1:45678",
		"ss+unix://./test.socks",
		"ss+unix://aes-256-gcm:p@./test.socks",
		"any+snappy://127.0.0.1:45678",
		"any+snappy://u:p@127.0.0.1:45678",
		"http+snappy://127.0.0.1:45678",
		"http+snappy://u:p@127.0.0.1:45678",
		"http+snappy+unix://./test.socks",
		"http+snappy+unix://u:p@./test.socks",
		"socks5+snappy://127.0.0.1:45678",
		"socks5+snappy://u:p@127.0.0.1:45678",
		"socks5+snappy+unix://./test.socks",
		"socks5+snappy+unix://u:p@./test.socks",
		"socks4+snappy://127.0.0.1:45678",
		"socks4+snappy://u:p@127.0.0.1:45678",
		"socks4+snappy+unix://./test.socks",
		"socks4+snappy+unix://u:p@./test.socks",
		"ssh+snappy://127.0.0.1:45678",
		"ssh+snappy://u:p@127.0.0.1:45678",
		"ssh+snappy+unix://./test.socks",
		"ssh+snappy+unix://u:p@./test.socks",
		"ss+snappy://127.0.0.1:45678",
		"ss+snappy://aes-256-gcm:p@127.0.0.1:45678",
		"ss+snappy+unix://./test.socks",
		"ss+snappy+unix://aes-256-gcm:p@./test.socks",
		"https://127.0.0.1:45678?tls_skip_verify=true&tls_self_signed=true",
		"https://u:p@127.0.0.1:45678?tls_skip_verify=true&tls_self_signed=true",
		"http+tls://127.0.0.1:45678?tls_skip_verify=true&tls_self_signed=true",
		"http+tls://u:p@127.0.0.1:45678?tls_skip_verify=true&tls_self_signed=true",
	}
	for _, uri := range testdata {
		t.Run(uri, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.Cleanup(cancel)
			runner, err := proxy.NewRunner(uri)
			if err != nil {
				t.Fatal(err)
			}

			done := make(chan struct{})
			go func() {
				err := runner.Run(ctx)
				if err != nil && !netutils.IsClosedConnError(err) {
					t.Fatal("runner.Run: ", err)
				}
				done <- struct{}{}
			}()
			t.Cleanup(func() {
				runner.Close()
			})
			time.Sleep(1 * time.Second)

			cliURI := uri
			if strings.HasPrefix(cliURI, "any") {
				protos := []string{
					"socks5",
					"socks4",
					"ssh",
					"http",
				}
				cliURI = protos[rand.Intn(len(protos))] + uri[3:]
			}
			dialer, err := proxy.NewDialer(cliURI)
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

			runner.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("expected runner to exit after 10 seconds but it didn't")
			}
		})
	}
}
