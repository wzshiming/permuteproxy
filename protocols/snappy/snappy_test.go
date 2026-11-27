package snappy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/snappy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/testutils"
	_ "github.com/wzshiming/permuteproxy/protocols/snappy"
)

// wire is a base network recording what the conns it dials write on their carrier.
type wire struct {
	permuteproxy.NetworkFuncs
	mu      sync.Mutex
	written bytes.Buffer
}

func (w *wire) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return recorded{conn, w}, nil
}

func (w *wire) sent() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.written.Bytes())
}

type recorded struct {
	net.Conn
	w *wire
}

func (c recorded) Write(b []byte) (int, error) {
	c.w.mu.Lock()
	c.w.written.Write(b)
	c.w.mu.Unlock()
	return c.Conn.Write(b)
}

func transport(t *testing.T, e permuteproxy.Engine, uri string) permuteproxy.Transport {
	t.Helper()
	c, err := permuteproxy.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := e.Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestDialTCPWithoutLocalIsUnsupported(t *testing.T) {
	// These tests link no protocols/local, so nothing registers tcp.
	if _, err := permuteproxy.ParseURI("tcp://127.0.0.1:1"); !errors.Is(err, permuteproxy.ErrInvalidChain) {
		t.Errorf("ParseURI naming tcp = %v, want ErrInvalidChain", err)
	}
	_, err := transport(t, permuteproxy.Engine{}, "snappy://127.0.0.1:1").Dial(context.Background(), permuteproxy.Stream)
	if !errors.Is(err, permuteproxy.ErrUnsupported) {
		t.Fatalf("Dial over the default tcp without a Base = %v, want ErrUnsupported", err)
	}
}

func TestRoundTripThroughEngine(t *testing.T) {
	const msg, reply = "hello snappy", "re: hello snappy"
	ln, err := transport(t, permuteproxy.Engine{Base: testutils.System{}}, "snappy://127.0.0.1:0").Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err == nil {
			conn.Write(append([]byte("re: "), got...))
		}
	}()
	base := &wire{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := transport(t, permuteproxy.Engine{Base: base}, "snappy://"+ln.Addr().String()).Dial(ctx, permuteproxy.Stream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != reply {
		t.Fatalf("reply = %q, %v; want %q", got, err, reply)
	}
	if sent, err := io.ReadAll(snappy.NewReader(bytes.NewReader(base.sent()))); err != nil || string(sent) != msg {
		t.Fatalf("carrier held %q, decoding to %q, %v; want snappy frames of %q", base.sent(), sent, err, msg)
	}
}
