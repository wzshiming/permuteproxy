package cmdutils

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/wzshiming/cmux"

	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// Dial starts a command whose stdio becomes the connection. Closing the conn ends the command's
// input; a conn that also implements netutils.Process lets callers follow the command's exit.
type Dial func(ctx context.Context, name string, args ...string) (net.Conn, error)

// DialContext starts the command; ctx only bounds the start, the conn then lives until Close
// cancels the context the command was started with.
func DialContext(ctx context.Context, dial Dial, localAddr, remoteAddr net.Addr, command []string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	own, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	stdio, err := dial(own, command[0], command[1:]...)
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	if !stop() {
		discard(stdio)
		return nil, ctx.Err()
	}
	var once sync.Once
	var closeErr error
	conn := netutils.ConnWithCloser(stdio, func() error {
		once.Do(func() {
			closeErr = stdio.Close()
			cancel()
		})
		return closeErr
	})
	return netutils.ConnWithAddr(conn, localAddr, remoteAddr), nil
}

// discard ends a command nobody will use: killed at once when it exposes its process.
func discard(conn net.Conn) {
	if p, ok := conn.(netutils.Process); ok {
		p.Kill()
	}
	conn.Close()
}

// Listen prepares a listener; ctx only bounds the call, the listener lives until Close. exitGrace
// bounds how long output a command wrote before exiting may take to arrive.
func Listen(ctx context.Context, dial Dial, localAddr, remoteAddr net.Addr, command []string, exitGrace time.Duration) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	own, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &listener{
		ctx:        own,
		cancel:     cancel,
		dial:       dial,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		command:    command,
		exitGrace:  exitGrace,
		accepting:  make(chan struct{}, 1),
	}, nil
}

type listener struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dial       Dial
	command    []string
	localAddr  net.Addr
	remoteAddr net.Addr
	exitGrace  time.Duration
	accepting  chan struct{}
	// gate is owned by the Accept holding accepting; pending is shared with Close.
	gate    <-chan struct{}
	mu      sync.Mutex
	pending net.Conn
}

// Accept starts one command and hands it over once the peer sends its first byte, the only
// signal a subprocess offers that a connection arrived. The command starts only after the
// previous one has exited, since its process still holds the listening address; a command that
// exits cleanly before any byte was seen is started again.
func (l *listener) Accept() (net.Conn, error) {
	select {
	case l.accepting <- struct{}{}:
		defer func() { <-l.accepting }()
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
	for {
		if l.gate != nil {
			select {
			case <-l.gate:
			case <-l.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		conn, err := DialContext(l.ctx, l.dial, l.localAddr, l.remoteAddr, l.command)
		if err != nil {
			if l.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		if !l.hold(conn) {
			discard(conn)
			return nil, net.ErrClosed
		}
		first, err := l.first(conn)
		if err == nil {
			if accepted := l.admit(conn, first); accepted != nil {
				return accepted, nil
			}
			return nil, net.ErrClosed
		}
		conn.Close()
		p, ok := conn.(netutils.Process)
		if ok {
			select {
			case <-p.Done():
			case <-l.ctx.Done():
			}
		}
		l.release(conn)
		if l.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		if !ok {
			return nil, err
		}
		if perr := p.Err(); perr != nil {
			return nil, perr
		}
		if !errors.Is(err, io.EOF) {
			return nil, err
		}
	}
}

// first reads the command's first byte; once its process has exited only output already on its
// way can follow, so the wait is then bounded by exitGrace since a descendant may hold stdout open.
func (l *listener) first(conn net.Conn) ([]byte, error) {
	var buf [1]byte
	read := make(chan error, 1)
	go func() {
		n, err := conn.Read(buf[:])
		if n > 0 {
			// A byte arriving with EOF still opens the connection; the EOF surfaces on the next Read.
			err = nil
		}
		read <- err
	}()
	var done <-chan struct{}
	if p, ok := conn.(netutils.Process); ok {
		done = p.Done()
	}
	select {
	case err := <-read:
		return buf[:], err
	case <-done:
	}
	if err := conn.SetReadDeadline(time.Now().Add(l.exitGrace)); !bounded(err) {
		conn.Close()
		<-read
		return nil, err
	}
	err := <-read
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = io.EOF
	}
	if rerr := conn.SetReadDeadline(time.Time{}); !bounded(rerr) {
		conn.Close()
		return nil, rerr
	}
	return buf[:], err
}

// bounded reports whether a read is bounded after SetReadDeadline returned err: the deadline took
// effect, or the conn refused it because it is already closed and so ends the read by itself.
func bounded(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// hold registers a started command as pending unless the listener already closed.
func (l *listener) hold(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx.Err() != nil {
		return false
	}
	l.pending = conn
	return true
}

func (l *listener) release(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == conn {
		l.pending = nil
	}
}

// admit hands the pending command over; after Close it returns nil and Close discards it.
func (l *listener) admit(conn net.Conn, first []byte) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx.Err() != nil {
		return nil
	}
	l.pending = nil
	accepted := netutils.WithProcess(cmux.UnreadConn(conn, first), conn)
	if p, ok := conn.(netutils.Process); ok {
		l.gate = p.Done()
		return accepted
	}
	released := make(chan struct{})
	l.gate = released
	var once sync.Once
	return netutils.ConnWithCloser(accepted, func() error {
		err := accepted.Close()
		once.Do(func() { close(released) })
		return err
	})
}

// Close kills the command nobody accepted yet; accepted connections stay usable.
func (l *listener) Close() error {
	l.mu.Lock()
	l.cancel()
	pending := l.pending
	l.pending = nil
	l.mu.Unlock()
	if pending != nil {
		discard(pending)
	}
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.localAddr
}
