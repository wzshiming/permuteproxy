package snappy

import (
	"context"
	"net"
	"sync"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/snappy"

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

// newConn writes the snappy framing format, each write compressed and sent on the calling goroutine so a conn starts none of its own.
func newConn(c net.Conn) net.Conn {
	w := s2.NewWriter(c, s2.WriterSnappyCompat(), s2.WriterFlushOnWrite(), s2.WriterConcurrency(1))
	return &conn{Conn: c, w: w, r: snappy.NewReader(c)}
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
	return c.w.Write(b)
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
