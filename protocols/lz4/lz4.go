package lz4

import (
	"context"
	"net"
	"sync"

	"github.com/pierrec/lz4/v4"

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
	w := lz4.NewWriter(c)
	// A write is flushed as its own block, so the smallest block size keeps a conn's buffers small; the option is valid, so Apply cannot fail.
	_ = w.Apply(lz4.BlockSizeOption(lz4.Block64Kb))
	return &conn{Conn: c, w: w, r: newReader(c)}
}

// conn guards its reader and writer, which keep buffers no two calls may share, as a net.Conn takes concurrent calls.
type conn struct {
	net.Conn
	wmu sync.Mutex
	w   *lz4.Writer
	rmu sync.Mutex
	r   *reader
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
