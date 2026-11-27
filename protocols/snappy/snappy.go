package snappy

import (
	"context"
	"net"
	"sync"

	"github.com/golang/snappy"

	"github.com/wzshiming/permuteproxy"
)

func NewAdapter(permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	return &permuteproxy.AdapterFuncs{Stream: &permuteproxy.Link{
		Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
			c, err := carrier(ctx)
			if err != nil {
				return nil, err
			}
			return newConn(c), nil
		},
		Listen: func(ctx context.Context, carrier func(context.Context) (net.Listener, error)) (net.Listener, error) {
			ln, err := carrier(ctx)
			if err != nil {
				return nil, err
			}
			return listener{ln}, nil
		},
	}}, nil
}

func newConn(c net.Conn) net.Conn {
	return &conn{Conn: c, w: snappy.NewBufferedWriter(c), r: snappy.NewReader(c)}
}

// conn guards its reader and writer, which keep buffers no two calls may share, as a net.Conn takes concurrent calls.
type conn struct {
	net.Conn
	wmu sync.Mutex
	w   *snappy.Writer
	rmu sync.Mutex
	r   *snappy.Reader
}

func (c *conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.r.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, err := c.w.Write(b)
	if err != nil {
		return n, err
	}
	return n, c.w.Flush()
}

type listener struct {
	net.Listener
}

func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}
