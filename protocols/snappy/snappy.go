package snappy

import (
	"context"
	"net"

	"github.com/golang/snappy"

	"github.com/wzshiming/permuteproxy"
)

func NewAdapter(permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	return &permuteproxy.AdapterFuncs{Stream: &permuteproxy.Link{
		Client: func(_ context.Context, carrier net.Conn) (net.Conn, error) {
			return newConn(carrier), nil
		},
		Listener: func(ln net.Listener) (net.Listener, error) {
			return listener{ln}, nil
		},
	}}, nil
}

func newConn(c net.Conn) net.Conn {
	return conn{Conn: c, w: snappy.NewBufferedWriter(c), r: snappy.NewReader(c)}
}

type conn struct {
	net.Conn
	w *snappy.Writer
	r *snappy.Reader
}

func (c conn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c conn) Write(b []byte) (int, error) {
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
