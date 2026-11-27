package zstd

import (
	"context"
	"net"
	"sync"

	"github.com/klauspost/compress/zstd"

	"github.com/wzshiming/permuteproxy"
)

func NewAdapter(permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	return &permuteproxy.AdapterFuncs{Stream: &permuteproxy.Link{
		Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
			c, err := carrier(ctx)
			if err != nil {
				return nil, err
			}
			return newConn(c)
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

// newConn builds a coder per direction, each working on the calling goroutine so a conn starts none of its own.
func newConn(c net.Conn) (net.Conn, error) {
	w, err := zstd.NewWriter(c, zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true))
	if err != nil {
		c.Close()
		return nil, err
	}
	r, err := zstd.NewReader(c, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
	if err != nil {
		c.Close()
		return nil, err
	}
	return &conn{Conn: c, w: w, r: r}, nil
}

// conn guards its reader and writer, which keep buffers no two calls may share, as a net.Conn takes concurrent calls.
type conn struct {
	net.Conn
	wmu sync.Mutex
	w   *zstd.Encoder
	rmu sync.Mutex
	r   *zstd.Decoder
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
	return newConn(c)
}
