package netutils

import (
	"net"
)

// Process is the lifecycle of the subprocess carrying a conn: Done closes once it has been
// reaped, Err then reports its exit error, Kill terminates it at once.
type Process interface {
	Done() <-chan struct{}
	Err() error
	Kill() error
}

type processConn struct {
	net.Conn
	Process
}

// ConnWithProcess makes the Process of inner visible again on a wrapper that embeds only net.Conn.
func ConnWithProcess(conn, inner net.Conn) net.Conn {
	if p, ok := inner.(Process); ok {
		return &processConn{Conn: conn, Process: p}
	}
	return conn
}

func ConnWithCloser(conn net.Conn, closer func() error) net.Conn {
	return ConnWithProcess(&connCloser{Conn: conn, closer: closer}, conn)
}

type connCloser struct {
	net.Conn
	closer func() error
}

func (w *connCloser) Close() error {
	return w.closer()
}

func ConnWithAddr(conn net.Conn, localAddr, remoteAddr net.Addr) net.Conn {
	return ConnWithProcess(&connAddr{Conn: conn, localAddr: localAddr, remoteAddr: remoteAddr}, conn)
}

type connAddr struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (w *connAddr) LocalAddr() net.Addr {
	if w.localAddr == nil {
		return w.Conn.LocalAddr()
	}
	return w.localAddr
}

func (w *connAddr) RemoteAddr() net.Addr {
	if w.remoteAddr == nil {
		return w.Conn.RemoteAddr()
	}
	return w.remoteAddr
}
