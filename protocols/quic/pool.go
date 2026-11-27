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

// idleKeep is how long the adapter keeps a connection no conn holds, for the next dial to find.
var idleKeep = 30 * time.Second

// pool is the connection an adapter's dials share: a dial opens a stream on it, so only a dial
// that finds none, or finds it full or ended, pays for a carrier and a handshake.
type pool struct {
	mu      sync.Mutex
	current *link
	closed  bool // the adapter was closed and keeps no connection idle
}

// link is one dialed connection and the socket it owns.
type link struct {
	pool          *pool
	endpoint      *quic.Endpoint
	qc            *quic.Conn
	local, remote net.Addr

	// The rest is guarded by pool.mu.
	holds    int         // dials opening a stream, and conns not yet released
	idle     *time.Timer // set while no hold keeps the connection, to release it after idleKeep
	released bool
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
	if l.idle != nil {
		// A timer that has fired finds the hold and leaves the connection alone.
		l.idle.Stop()
		l.idle = nil
	}
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

// close releases the connection kept idle; the conns still open keep theirs until they close.
func (p *pool) close() error {
	p.mu.Lock()
	p.closed = true
	l := p.current
	release := l != nil && l.releaseLocked()
	p.mu.Unlock()
	if release {
		closeEndpoint(l.endpoint)
	}
	return nil
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
	if l.pool.current == l {
		l.pool.current = nil
	}
}

// done drops one hold; once the last is dropped, the connection is released at once when no
// dial can find it, else after it has stayed idle for idleKeep.
func (l *link) done() {
	p := l.pool
	p.mu.Lock()
	l.holds--
	release := false
	switch {
	case l.holds > 0:
	case p.current != l || p.closed || idleKeep <= 0:
		release = l.releaseLocked()
	default:
		l.idle = time.AfterFunc(idleKeep, l.expire)
	}
	p.mu.Unlock()
	if release {
		closeEndpoint(l.endpoint)
	}
}

// expire releases the connection unless a dial took it since its timer was set.
func (l *link) expire() {
	l.pool.mu.Lock()
	release := l.releaseLocked()
	l.pool.mu.Unlock()
	if release {
		closeEndpoint(l.endpoint)
	}
}

// releaseLocked takes a connection without holds out of the pool and reports whether the caller is the one to close it.
func (l *link) releaseLocked() bool {
	if l.holds > 0 || l.released {
		return false
	}
	l.released = true
	if l.idle != nil {
		l.idle.Stop()
		l.idle = nil
	}
	if l.pool.current == l {
		l.pool.current = nil
	}
	return true
}
