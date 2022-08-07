package protocols_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/protocols"
	_ "github.com/wzshiming/permuteproxy/protocols/http"
	_ "github.com/wzshiming/permuteproxy/protocols/local"
	_ "github.com/wzshiming/permuteproxy/protocols/snappy"
	_ "github.com/wzshiming/permuteproxy/protocols/socks4"
	_ "github.com/wzshiming/permuteproxy/protocols/socks5"
)

func TestTCPListenAndDial(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
	uri := "tcp://127.0.0.1:45656"
	listenConn, _, err := protocols.NewListenConfig(nil, uri)
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

	_, dialConn, err := protocols.NewDialer(nil, uri)
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
		"http://127.0.0.1:45656",
		"http+unix://./test.socs",
		"socks5://127.0.0.1:45656",
		"socks5+unix://./test.socs",
		"socks4://127.0.0.1:45656",
		"socks4+unix://./test.socs",

		"http+snappy://127.0.0.1:45656",
		"http+snappy+unix://./test.socs",
		"socks5+snappy://127.0.0.1:45656",
		"socks5+snappy+unix://./test.socs",
		"socks4+snappy://127.0.0.1:45656",
		"socks4+snappy+unix://./test.socs",
	}
	for _, uri := range testdata {
		t.Run(uri, func(t *testing.T) {
			ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
			_, runner, err := protocols.NewListenConfig(nil, uri)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				err := runner.Run(ctx)
				if err != nil && !netutils.IsClosedConnError(err) {
					t.Fatal(err)
				}
			}()
			defer runner.Close()
			time.Sleep(time.Second / 10)

			dialer, _, err := protocols.NewDialer(nil, uri)
			if err != nil {
				t.Fatal(err)
			}

			want := "OK"
			testserver := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.Write([]byte(want))
			}))
			defer testserver.Close()
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

			body, _ := io.ReadAll(resp.Body)
			if want != string(body) {
				t.Fatalf("got %q, want %q", body, want)
			}
		})
	}
}
