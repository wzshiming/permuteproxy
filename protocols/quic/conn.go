package quic

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/quic"

	"github.com/wzshiming/permuteproxy"
)

// conn is a net.Conn over one QUIC stream; release, when set, frees the connection a Dial opened for it.
type conn struct {
	stream        *quic.Stream
	local, remote net.Addr
	release       func()
	once          sync.Once
}

func newConn(stream *quic.Stream, local, remote net.Addr, release func()) *conn {
	return &conn{stream: stream, local: local, remote: remote, release: release}
}

func (c *conn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.stream.Write(b)
	if err != nil {
		return n, err
	}
	return n, c.stream.Flush()
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

func (c *conn) SetDeadline(time.Time) error {
	return fmt.Errorf("deadline: %w", permuteproxy.ErrUnsupported)
}

func (c *conn) SetReadDeadline(time.Time) error {
	return fmt.Errorf("deadline: %w", permuteproxy.ErrUnsupported)
}

func (c *conn) SetWriteDeadline(time.Time) error {
	return fmt.Errorf("deadline: %w", permuteproxy.ErrUnsupported)
}
