package netutils

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// SessionOptions bounds the sessions NewSessions keeps open.
type SessionOptions struct {
	// IdleTimeout closes a session without reads or writes for this long; zero means one minute.
	IdleTimeout time.Duration
	// MaxSessions caps the open sessions, closing the least recently active first; zero means 64.
	MaxSessions int
}

var (
	errMissingPeer    = errors.New("missing peer address")
	errSessionEvicted = errors.New("session evicted to stay within MaxSessions")
)

const (
	defaultIdleTimeout = time.Minute
	defaultMaxSessions = 64
	// sessionReadSize holds the largest UDP payload, so one session Read never splits a datagram.
	sessionReadSize = 64 << 10
)

var sessionBuffers = sync.Pool{New: func() any { return new([sessionReadSize]byte) }}

// NewSessions is a net.PacketConn carrying each peer's datagrams over its own conn, dialed on first write.
// Its Close waits for the session readers, so a session conn's Close must unblock its own pending Read.
func NewSessions(dial func(ctx context.Context, peer net.Addr) (net.Conn, error), opts SessionOptions) net.PacketConn {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = defaultIdleTimeout
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = defaultMaxSessions
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &sessions{
		dial:          dial,
		opts:          opts,
		ctx:           ctx,
		cancel:        cancel,
		chunks:        make(chan chunk),
		readDeadline:  newDeadline(),
		writeDeadline: newDeadline(),
		peers:         map[sessionKey]*session{},
	}
}

type sessionKey struct{ network, address string }

type session struct {
	key    sessionKey
	peer   net.Addr
	cancel context.CancelFunc // ends the context conn was dialed with
	ready  chan struct{}      // closed once conn or err is set
	done   chan struct{}      // closed with the session
	conn   net.Conn
	err    error

	// The rest is guarded by sessions.mu.
	closed bool
	used   uint64 // rank of the last activity, for eviction
	active time.Time
	timer  *time.Timer
}

// chunk is one Read of a session's conn on its way to ReadFrom.
type chunk struct {
	buf  *[sessionReadSize]byte
	n    int
	peer net.Addr
}

type sessions struct {
	dial          func(ctx context.Context, peer net.Addr) (net.Conn, error)
	opts          SessionOptions
	ctx           context.Context // ends with Close
	cancel        context.CancelFunc
	chunks        chan chunk
	readers       sync.WaitGroup
	readDeadline  *deadline
	writeDeadline *deadline

	mu        sync.Mutex
	peers     map[sessionKey]*session
	clock     uint64
	writeTime time.Time // the write deadline every session conn carries
}

func (s *sessions) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errMissingPeer
	}
	sess, err := s.open(addr, s.writeDeadline.context())
	if err != nil {
		return 0, err
	}
	n, err := sess.conn.Write(b)
	var ne net.Error
	switch {
	case err == nil:
	case s.ctx.Err() != nil:
		err = net.ErrClosed
	case !errors.As(err, &ne) || !ne.Timeout():
		s.drop(sess)
	}
	return n, err
}

// open returns the session to peer, dialing it unless another WriteTo already did or is doing so.
func (s *sessions) open(peer net.Addr, expired context.Context) (*session, error) {
	key := sessionKey{peer.Network(), peer.String()}
	s.mu.Lock()
	switch {
	case s.ctx.Err() != nil:
		s.mu.Unlock()
		return nil, net.ErrClosed
	case expired.Err() != nil:
		s.mu.Unlock()
		return nil, os.ErrDeadlineExceeded
	}
	if sess, ok := s.peers[key]; ok {
		s.touchLocked(sess)
		s.mu.Unlock()
		<-sess.ready
		if sess.err != nil {
			return nil, sess.err
		}
		return sess, nil
	}
	stale := s.evictLocked()
	ctx, cancel := context.WithCancel(s.ctx)
	sess := &session{key: key, peer: peer, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{})}
	s.touchLocked(sess)
	s.peers[key] = sess
	s.mu.Unlock()
	if stale != nil {
		stale.Close()
	}
	stop := context.AfterFunc(expired, cancel)
	conn, err := s.dial(ctx, peer)
	inTime := stop()
	s.mu.Lock()
	evicted := sess.closed
	if err == nil && !evicted {
		sess.conn = conn
		conn.SetWriteDeadline(s.writeTime)
		sess.timer = time.AfterFunc(s.opts.IdleTimeout, func() { s.expire(sess) })
		s.readers.Add(1)
		go s.read(sess)
		s.mu.Unlock()
		close(sess.ready)
		return sess, nil
	}
	s.closeLocked(sess)
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	switch {
	case s.ctx.Err() != nil:
		err = net.ErrClosed
	case evicted:
		err = errSessionEvicted
	case !inTime:
		err = os.ErrDeadlineExceeded
	}
	sess.err = err
	close(sess.ready)
	return nil, err
}

// read hands each chunk the session reads to ReadFrom and closes the session once its conn fails.
func (s *sessions) read(sess *session) {
	defer s.readers.Done()
	defer s.drop(sess)
	for {
		buf := sessionBuffers.Get().(*[sessionReadSize]byte)
		n, err := sess.conn.Read(buf[:])
		if n == 0 {
			sessionBuffers.Put(buf)
		} else {
			s.mu.Lock()
			s.touchLocked(sess)
			s.mu.Unlock()
			select {
			case s.chunks <- chunk{buf: buf, n: n, peer: sess.peer}:
			case <-sess.done:
				sessionBuffers.Put(buf)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// expire closes sess once it has gone a whole idle timeout without a read or write.
func (s *sessions) expire(sess *session) {
	s.mu.Lock()
	var conn net.Conn
	switch rest := s.opts.IdleTimeout - time.Since(sess.active); {
	case sess.closed:
	case rest > 0:
		sess.timer.Reset(rest)
	default:
		conn = s.closeLocked(sess)
	}
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (s *sessions) drop(sess *session) {
	s.mu.Lock()
	conn := s.closeLocked(sess)
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// closeLocked forgets sess and stops its dial, timer and reader, returning the conn left to close.
func (s *sessions) closeLocked(sess *session) net.Conn {
	if sess.closed {
		return nil
	}
	sess.closed = true
	delete(s.peers, sess.key)
	sess.cancel()
	close(sess.done)
	if sess.timer != nil {
		sess.timer.Stop()
	}
	return sess.conn
}

func (s *sessions) touchLocked(sess *session) {
	s.clock++
	sess.used = s.clock
	sess.active = time.Now()
}

// evictLocked closes the least recently active session when the cap leaves no room for another.
func (s *sessions) evictLocked() net.Conn {
	if len(s.peers) < s.opts.MaxSessions {
		return nil
	}
	var lru *session
	for _, sess := range s.peers {
		if lru == nil || sess.used < lru.used {
			lru = sess
		}
	}
	return s.closeLocked(lru)
}

func (s *sessions) ReadFrom(b []byte) (int, net.Addr, error) {
	expired := s.readDeadline.context()
	switch {
	case s.ctx.Err() != nil:
		return 0, nil, net.ErrClosed
	case expired.Err() != nil:
		return 0, nil, os.ErrDeadlineExceeded
	}
	select {
	case c := <-s.chunks:
		n := copy(b, c.buf[:c.n])
		sessionBuffers.Put(c.buf)
		return n, c.peer, nil
	case <-s.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-expired.Done():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (s *sessions) Close() error {
	s.mu.Lock()
	s.cancel()
	var conns []net.Conn
	for _, sess := range s.peers {
		if conn := s.closeLocked(sess); conn != nil {
			conns = append(conns, conn)
		}
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, conn := range conns {
		closing.Go(func() { conn.Close() })
	}
	closing.Wait()
	s.readers.Wait()
	return nil
}

func (s *sessions) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (s *sessions) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *sessions) SetReadDeadline(t time.Time) error {
	s.readDeadline.set(t)
	return nil
}

// SetWriteDeadline bounds dials through the deadline and writes through every session conn.
func (s *sessions) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline.set(t)
	s.writeTime = t
	for _, sess := range s.peers {
		if sess.conn != nil {
			sess.conn.SetWriteDeadline(t)
		}
	}
	return nil
}

// deadline is a movable instant whose context ends once it passes.
type deadline struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	timer  *time.Timer
}

func newDeadline() *deadline {
	d := &deadline{}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	return d
}

// context ends when the deadline passes; moving the deadline keeps it unless it already ended.
func (d *deadline) context() context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ctx
}

// set moves the deadline to t; the zero time clears it.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.ctx.Done()
	}
	d.timer = nil
	if d.ctx.Err() != nil {
		d.ctx, d.cancel = context.WithCancel(context.Background())
	}
	switch wait := time.Until(t); {
	case t.IsZero():
	case wait > 0:
		d.timer = time.AfterFunc(wait, d.cancel)
	default:
		d.cancel()
	}
}
