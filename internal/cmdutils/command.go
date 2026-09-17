package cmdutils

import (
	"context"
	"net"
	"sync"

	"github.com/wzshiming/cmux"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// Dial starts a command whose stdio becomes the connection. Closing the conn ends the command's
// input and returns once the command has exited; cancelling ctx kills it.
type Dial func(ctx context.Context, name string, args ...string) (net.Conn, error)

func DialContext(ctx context.Context, dial Dial, localAddr, remoteAddr net.Addr, command []string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stdio, err := dial(ctx, command[0], command[1:]...)
	if err != nil {
		cancel()
		return nil, err
	}
	conn := netutils.ConnWithCloser(stdio, func() error {
		err := stdio.Close()
		cancel()
		return err
	})
	return netutils.ConnWithAddr(conn, localAddr, remoteAddr), nil
}

func Listen(ctx context.Context, dial Dial, localAddr, remoteAddr net.Addr, command []string) (net.Listener, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &listener{
		ctx:        ctx,
		cancel:     cancel,
		dial:       dial,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		command:    command,
	}, nil
}

type listener struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dial       Dial
	command    []string
	localAddr  net.Addr
	remoteAddr net.Addr
	mu         sync.Mutex
	released   <-chan struct{}
}

type accepted struct {
	conn net.Conn
	err  error
}

// Accept starts one command and hands it over once the peer sends its first byte, the only
// signal a subprocess offers that a connection arrived. The command starts only after the
// previous connection has been closed, since its process still holds the listening address.
func (l *listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released != nil {
		select {
		case <-l.released:
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		}
	}
	if l.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	results := make(chan accepted, 1)
	go func() {
		conn, err := DialContext(l.ctx, l.dial, l.localAddr, l.remoteAddr, l.command)
		if err != nil {
			results <- accepted{err: err}
			return
		}
		stop := context.AfterFunc(l.ctx, func() { conn.Close() })
		var first [1]byte
		_, err = conn.Read(first[:])
		stop()
		if err != nil {
			conn.Close()
			results <- accepted{err: err}
			return
		}
		results <- accepted{conn: cmux.UnreadConn(conn, first[:])}
	}()
	select {
	case <-l.ctx.Done():
		go func() {
			if r := <-results; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, net.ErrClosed
	case r := <-results:
		if r.err != nil {
			return nil, r.err
		}
		released := make(chan struct{})
		l.released = released
		var once sync.Once
		return netutils.ConnWithCloser(r.conn, func() error {
			err := r.conn.Close()
			once.Do(func() { close(released) })
			return err
		}), nil
	}
}

func (l *listener) Close() error {
	l.cancel()
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.localAddr
}
