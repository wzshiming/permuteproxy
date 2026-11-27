package quic

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/net/quic"
)

// maxStreams caps the conns sharing one connection, below the 100 streams x/net/quic lets a peer open.
const maxStreams = 64

// openWait bounds how long a dial waits for a stream of a shared connection before it opens its own;
// at the peer's stream limit a stream opens only once another closes, which may be never.
var openWait = time.Second

// pool is the connection an adapter's dials share: a dial opens a stream on it while a conn of
// an earlier dial still holds it, so only the first of concurrent conns pays for a handshake.
type pool struct {
	mu      sync.Mutex
	current *link
}

// link is one dialed connection and the socket it owns, released once the last conn on it has closed.
type link struct {
	pool          *pool
	endpoint      *quic.Endpoint
	qc            *quic.Conn
	local, remote net.Addr
	holds         int // dials opening a stream, and conns not yet released; guarded by pool.mu
}

// acquire holds the pool's connection for one more dial, if it has one with room.
func (p *pool) acquire() *link {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.current
	if l == nil || l.holds >= maxStreams {
		return nil
	}
	l.holds++
	return l
}

// add holds a freshly dialed connection for its dial and shares it unless the pool has one already.
func (p *pool) add(endpoint *quic.Endpoint, qc *quic.Conn, local, remote net.Addr) *link {
	l := &link{pool: p, endpoint: endpoint, qc: qc, local: local, remote: remote, holds: 1}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current == nil {
		p.current = l
	}
	return l
}

// open opens a stream that reaches the peer at once, so a listener that speaks first sees it.
func (l *link) open(ctx context.Context) (*quic.Stream, error) {
	stream, err := l.qc.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	stream.Flush()
	return stream, nil
}

// retire keeps later dials off the connection; the conns on it keep it until they close.
func (l *link) retire() {
	l.pool.mu.Lock()
	defer l.pool.mu.Unlock()
	l.retireLocked()
}

func (l *link) retireLocked() {
	if l.pool.current == l {
		l.pool.current = nil
	}
}

// done drops one hold; the last one closes the connection and its socket.
func (l *link) done() {
	l.pool.mu.Lock()
	l.holds--
	last := l.holds == 0
	if last {
		l.retireLocked()
	}
	l.pool.mu.Unlock()
	if last {
		closeEndpoint(l.endpoint)
	}
}
