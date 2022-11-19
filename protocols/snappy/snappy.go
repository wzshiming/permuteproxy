package snappy

import (
	"context"
	"net"

	"github.com/golang/snappy"
	"github.com/wzshiming/permuteproxy"
)

func NewSnappyDialer(dialer permuteproxy.Dialer, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	return snappyDialer{dialer}, nil
}

func NewSnappyListenConfig(listenConfig permuteproxy.ListenConfig, metadata permuteproxy.Metadata) (permuteproxy.ListenConfig, error) {
	return snappyListenConfig{listenConfig}, nil
}

type snappyDialer struct {
	dialer permuteproxy.Dialer
}

func (n snappyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := n.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn := newWarpConn(c)
	return conn, nil
}

type snappyListenConfig struct {
	listenConfig permuteproxy.ListenConfig
}

func (n snappyListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := n.listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return wrapListener{l}, nil
}

func newWarpConn(conn net.Conn) net.Conn {
	w := snappy.NewBufferedWriter(conn)
	r := snappy.NewReader(conn)
	return wrapConn{
		Conn: conn,
		w:    w,
		r:    r,
	}
}

type wrapConn struct {
	net.Conn
	w *snappy.Writer
	r *snappy.Reader
}

func (w wrapConn) Read(b []byte) (int, error) {
	return w.r.Read(b)
}

func (w wrapConn) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err != nil {
		return n, err
	}
	err = w.w.Flush()
	if err != nil {
		return n, err
	}
	return n, nil
}

type wrapListener struct {
	net.Listener
}

func (w wrapListener) Accept() (net.Conn, error) {
	c, err := w.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newWarpConn(c), nil
}
