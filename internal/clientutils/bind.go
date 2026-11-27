// Package clientutils holds what the clients of several proxy protocols share.
package clientutils

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// BindFunc asks a proxy over a new control conn to listen at address and returns the conn with the address the proxy bound.
type BindFunc func(ctx context.Context, address string) (conn net.Conn, bound net.Addr, err error)

// WaitFunc blocks until the proxy reports the peer it accepted for the request sent over conn, which then carries that peer's bytes.
type WaitFunc func(conn net.Conn) (peer net.Addr, err error)

// ListenBind listens at address on a proxy whose BIND request accepts one connection each: a
// request stays pending at the bound address, and as soon as it yields a connection the next
// is sent, so the address is left unbound only in between. Addr is what the first request
// bound; a later request that binds another port fails the listener. ctx bounds the first
// request only.
func ListenBind(ctx context.Context, address string, bind BindFunc, wait WaitFunc) (net.Listener, error) {
	conn, bound, err := bind(ctx, address)
	if err != nil {
		return nil, err
	}
	l := &bindListener{bind: bind, wait: wait, address: address, addr: bound, pending: conn, conns: make(chan net.Conn), done: make(chan struct{})}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	go l.run(conn)
	return l, nil
}

type bindListener struct {
	bind    BindFunc
	wait    WaitFunc
	address string
	addr    net.Addr
	ctx     context.Context // ends on Close
	cancel  context.CancelFunc
	conns   chan net.Conn
	done    chan struct{} // closes once run has ended and err is set

	mu      sync.Mutex
	closed  bool
	pending net.Conn // the control conn of the request in flight
	err     error
}

// run turns each granted request into an accepted conn, sending the next request while it hands the conn over.
func (l *bindListener) run(conn net.Conn) {
	defer close(l.done)
	for {
		peer, err := l.wait(conn)
		if err != nil {
			conn.Close()
			l.fail(err)
			return
		}
		accepted := &boundConn{Conn: conn, local: l.addr, remote: peer}
		handed := make(chan struct{})
		go func() {
			defer close(handed)
			select {
			case l.conns <- accepted:
			case <-l.ctx.Done():
				accepted.Close()
			}
		}()
		conn, err = l.rebind()
		// One conn waits for Accept at a time, and a failure is reported only after it.
		<-handed
		if err != nil {
			l.fail(err)
			return
		}
	}
}

// rebind sends the next request: for the address asked first, which a proxy that reuses its
// listener answers at the same port, and else for the port the listener has.
func (l *bindListener) rebind() (net.Conn, error) {
	for _, address := range []string{l.address, l.fixed()} {
		conn, bound, err := l.bind(l.ctx, address)
		switch {
		case err != nil:
			return nil, err
		case !l.hold(conn):
			return nil, net.ErrClosed
		case port(bound) == port(l.addr):
			return conn, nil
		}
		conn.Close()
	}
	return nil, fmt.Errorf("proxy no longer binds %v", l.addr)
}

// fixed is the address asked first with the port the listener has, which differs when port 0 was asked.
func (l *bindListener) fixed() string {
	host, _, _ := net.SplitHostPort(l.address)
	return net.JoinHostPort(host, port(l.addr))
}

func port(addr net.Addr) string {
	_, p, _ := net.SplitHostPort(addr.String())
	return p
}

// hold keeps conn as the request in flight, or closes it when Close came first.
func (l *bindListener) hold(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		conn.Close()
		return false
	}
	l.pending = conn
	return true
}

// fail records why run ended, unless Close did it.
func (l *bindListener) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		err = net.ErrClosed
	}
	l.err = err
}

func (l *bindListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, &net.OpError{Op: "accept", Net: l.addr.Network(), Addr: l.addr, Err: l.err}
	}
}

// Close ends the request in flight; the conns already accepted stay open.
func (l *bindListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	l.closed = true
	l.cancel()
	l.pending.Close()
	return nil
}

func (l *bindListener) Addr() net.Addr { return l.addr }

// boundConn is an accepted control conn, between the address the proxy bound and the peer it accepted.
type boundConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *boundConn) LocalAddr() net.Addr  { return c.local }
func (c *boundConn) RemoteAddr() net.Addr { return c.remote }

// Handshake runs do, which talks over conn, for at most timeout and fails once that passes or
// ctx ends. It interrupts do through a deadline on conn, or by closing a conn that takes none,
// as an ssh channel does; a conn whose handshake succeeded is left without a deadline.
func Handshake(ctx context.Context, conn net.Conn, timeout time.Duration, do func() error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		if conn.SetDeadline(time.Unix(1, 0)) != nil {
			conn.Close()
		}
	})
	err := do()
	if !stop() {
		return ctx.Err()
	}
	return err
}
