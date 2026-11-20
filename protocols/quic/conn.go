package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/quic"
)

// conn is a net.Conn over one QUIC stream; release, when set, frees the connection a Dial opened for it.
type conn struct {
	stream          *quic.Stream
	local, remote   net.Addr
	release         func()
	readMu, writeMu sync.Mutex // a stream takes one Read and one Write at a time
	rd, wd          *deadline
	once            sync.Once
}

func newConn(stream *quic.Stream, local, remote net.Addr, release func()) *conn {
	return &conn{stream: stream, local: local, remote: remote, release: release, rd: newDeadline(), wd: newDeadline()}
}

func (c *conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	done := c.rd.wait()
	if expired(done) {
		return 0, c.opError("read", os.ErrDeadlineExceeded)
	}
	c.stream.SetReadContext(waitCtx{context.Background(), done})
	n, err := c.stream.Read(b)
	if err != nil && err != io.EOF {
		err = c.opError("read", err)
	}
	return n, err
}

func (c *conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	done := c.wd.wait()
	if expired(done) {
		return 0, c.opError("write", os.ErrDeadlineExceeded)
	}
	c.stream.SetWriteContext(waitCtx{context.Background(), done})
	n, err := c.stream.Write(b)
	// What a Write took is sent at once, also when its deadline cut it short.
	if ferr := c.stream.Flush(); err == nil {
		err = ferr
	}
	if err != nil {
		return n, c.opError("write", err)
	}
	return n, nil
}

func (c *conn) opError(op string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		err = os.ErrDeadlineExceeded
	}
	return &net.OpError{Op: op, Net: "quic", Source: c.local, Addr: c.remote, Err: err}
}

func (c *conn) Close() error {
	c.once.Do(func() {
		if c.release == nil {
			c.stream.CloseRead()
			c.stream.CloseWrite()
			return
		}
		// Closing the connection discards what the peer has not acknowledged, so the stream's Close waits for that first.
		c.stream.Close()
		c.release()
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.local
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *conn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}

// waitCtx is what a stream operation blocks under: done once its deadline passes.
type waitCtx struct {
	context.Context
	done <-chan struct{}
}

func (w waitCtx) Done() <-chan struct{} {
	return w.done
}

func (w waitCtx) Err() error {
	if expired(w.done) {
		return context.DeadlineExceeded
	}
	return nil
}

func expired(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// deadline closes its channel once its time passes, as net.Pipe's does; a later time renews it.
type deadline struct {
	mu    sync.Mutex
	timer *time.Timer
	done  chan struct{}
}

func newDeadline() *deadline {
	return &deadline{done: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.done // the timer has fired: wait until it has closed done
	}
	d.timer = nil
	passed := expired(d.done)
	if t.IsZero() {
		if passed {
			d.done = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if passed {
			d.done = make(chan struct{})
		}
		done := d.done
		d.timer = time.AfterFunc(dur, func() { close(done) })
		return
	}
	if !passed {
		close(d.done)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.done
}
