package sshproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// forwards routes the forwarded-tcpip channels of one connection to its listeners. The x/crypto
// client drops a channel that names another address than the one asked, and servers differ in
// the address they name: the one asked, as OpenSSH does, or always 0.0.0.0, as sshd does.
type forwards struct {
	once sync.Once
	mu   sync.Mutex // also held while a request is pending, so that its first channel finds the listener
	lns  map[*forwardListener]struct{}
	gone bool // the connection ended
}

// forwardMsg is the payload of tcpip-forward and cancel-tcpip-forward (RFC 4254, 7.1).
type forwardMsg struct {
	Addr string
	Port uint32
}

// forwardedMsg is the payload of a forwarded-tcpip channel (RFC 4254, 7.2).
type forwardedMsg struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// listenTCP asks the server to listen at address and forward what it accepts over l.
func (l *link) listenTCP(address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("ssh: listen %s: port is not a number from 0 to 65535", address)
	}
	f := &l.fwd
	f.once.Do(func() {
		f.lns = map[*forwardListener]struct{}{}
		go f.serve(l.HandleChannelOpen("forwarded-tcpip"))
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gone {
		return nil, fmt.Errorf("ssh: listen %s: %w", address, io.EOF)
	}
	msg := forwardMsg{Addr: host, Port: uint32(portnum)}
	ok, reply, err := l.SendRequest("tcpip-forward", true, ssh.Marshal(msg))
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, errors.New("ssh: tcpip-forward request denied by peer")
	}
	if msg.Port == 0 {
		var bound struct{ Port uint32 }
		if err := ssh.Unmarshal(reply, &bound); err != nil {
			return nil, err
		}
		msg.Port = bound.Port
	}
	ln := &forwardListener{link: l, msg: msg, conns: make(chan net.Conn), done: make(chan struct{})}
	f.lns[ln] = struct{}{}
	return ln, nil
}

// serve hands each channel to its listener until the connection ends, which ends the listeners.
func (f *forwards) serve(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		go f.route(ch)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gone = true
	for ln := range f.lns {
		ln.end()
	}
	f.lns = nil
}

func (f *forwards) route(newCh ssh.NewChannel) {
	var msg forwardedMsg
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "could not parse forwarded-tcpip payload")
		return
	}
	ln := f.find(msg.Addr, msg.Port)
	if ln == nil {
		newCh.Reject(ssh.Prohibited, "no forward for address")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	origin := netutils.NewNetAddr("tcp", net.JoinHostPort(msg.OriginAddr, strconv.Itoa(int(msg.OriginPort))))
	select {
	case ln.conns <- &forwardConn{Channel: ch, local: ln.Addr(), remote: origin}:
	case <-ln.done:
		ch.Close()
	}
}

// find is the listener at port that asked for addr, else the only one at port.
func (f *forwards) find(addr string, port uint32) *forwardListener {
	f.mu.Lock()
	defer f.mu.Unlock()
	var only *forwardListener
	n := 0
	for ln := range f.lns {
		if ln.msg.Port != port {
			continue
		}
		if ln.msg.Addr == addr {
			return ln
		}
		only = ln
		n++
	}
	if n != 1 {
		return nil
	}
	return only
}

// forwardListener accepts what the server forwards from the address it listens at for one tcpip-forward request.
type forwardListener struct {
	link  *link
	msg   forwardMsg // the address asked, with the port the server bound
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func (ln *forwardListener) end() {
	ln.once.Do(func() { close(ln.done) })
}

func (ln *forwardListener) Accept() (net.Conn, error) {
	select {
	case conn := <-ln.conns:
		return conn, nil
	case <-ln.done:
		ln.link.fwd.mu.Lock()
		gone := ln.link.fwd.gone
		ln.link.fwd.mu.Unlock()
		if gone {
			return nil, io.EOF
		}
		return nil, net.ErrClosed
	}
}

// Close cancels the forward, without waiting for the server to confirm it.
func (ln *forwardListener) Close() error {
	f := &ln.link.fwd
	f.mu.Lock()
	_, held := f.lns[ln]
	delete(f.lns, ln)
	f.mu.Unlock()
	ln.end()
	if !held {
		return nil
	}
	_, _, err := ln.link.SendRequest("cancel-tcpip-forward", false, ssh.Marshal(ln.msg))
	return err
}

func (ln *forwardListener) Addr() net.Addr {
	if ip := net.ParseIP(ln.msg.Addr); ip != nil {
		return &net.TCPAddr{IP: ip, Port: int(ln.msg.Port)}
	}
	return netutils.NewNetAddr("tcp", net.JoinHostPort(ln.msg.Addr, strconv.Itoa(int(ln.msg.Port))))
}

// forwardConn is a forwarded channel between the address the server listens at and the peer it accepted.
type forwardConn struct {
	ssh.Channel
	local, remote net.Addr
}

func (c *forwardConn) LocalAddr() net.Addr              { return c.local }
func (c *forwardConn) RemoteAddr() net.Addr             { return c.remote }
func (c *forwardConn) SetDeadline(time.Time) error      { return errNoDeadline }
func (c *forwardConn) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (c *forwardConn) SetWriteDeadline(time.Time) error { return errNoDeadline }
