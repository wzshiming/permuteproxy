package local

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

func (l *Local) dialNetcatUnix(ctx context.Context, address string) (net.Conn, error) {
	dial, err := l.dial()
	if err != nil {
		return nil, err
	}
	return cmdutils.DialContext(ctx, dial, localAddr, netutils.NewNetAddr("cmd", "nc -U "+address), []string{"nc", "-U", address})
}

// listenNetcatUnix removes the socket file each nc leaves behind, but only one this listener can
// vouch for: a peer connected through it, or the path was empty when nc started and nc did not
// fail on its own; the file must also still be the inode recorded then. A foreign file at the
// path only makes nc fail; a competitor swapping the file while nc idles cannot be told apart.
func (l *Local) listenNetcatUnix(ctx context.Context, address string) (net.Listener, error) {
	dial, err := l.dial()
	if err != nil {
		return nil, err
	}
	socket := &socketFile{path: address}
	spawn := func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		socket.before()
		_, statErr := os.Lstat(address)
		conn, err := dial(ctx, name, args...)
		if err != nil {
			return nil, err
		}
		return socket.track(conn, os.IsNotExist(statErr)), nil
	}
	ln, err := cmdutils.Listen(ctx, spawn, localAddr, netutils.NewNetAddr("cmd", "nc -Ul "+address), []string{"nc", "-Ul", address})
	if err != nil {
		return nil, err
	}
	return &socketListener{Listener: ln, socket: socket}, nil
}

type socketFile struct {
	path  string
	mu    sync.Mutex
	owned os.FileInfo
	last  *spawn
}

// served claims the socket on the first byte a peer sends through nc, the proof that nc bound it.
type served struct {
	net.Conn
	socket *socketFile
	seen   atomic.Bool
}

func (c *served) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.seen.CompareAndSwap(false, true) {
		c.socket.claim()
	}
	return n, err
}

// spawn adds the exit bookkeeping for an nc that exposes its process.
type spawn struct {
	*served
	netutils.Process
	killed  atomic.Bool
	settled chan struct{}
}

func (s *spawn) Kill() error {
	s.killed.Store(true)
	return s.Process.Kill()
}

// track judges each nc once it has exited: one no peer reached owns the socket only if the path
// was empty beforehand and it exited cleanly or was killed here, since a failed bind fails nc.
func (s *socketFile) track(conn net.Conn, absent bool) net.Conn {
	sc := &served{Conn: conn, socket: s}
	p, ok := conn.(netutils.Process)
	if !ok {
		return sc
	}
	sp := &spawn{served: sc, Process: p, settled: make(chan struct{})}
	s.mu.Lock()
	s.last = sp
	s.mu.Unlock()
	go func() {
		<-p.Done()
		if !sc.seen.Load() && absent && (p.Err() == nil || sp.killed.Load()) {
			s.claim()
		}
		s.removeOwned()
		close(sp.settled)
	}()
	return sp
}

// before lets the previous nc be judged and its socket removed so the next one can bind the path.
func (s *socketFile) before() {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last != nil {
		<-last.settled
	}
	s.removeOwned()
}

func (s *socketFile) claim() {
	fi, err := os.Lstat(s.path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return
	}
	s.mu.Lock()
	s.owned = fi
	s.mu.Unlock()
}

func (s *socketFile) removeOwned() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owned == nil {
		return
	}
	if fi, err := os.Lstat(s.path); err == nil && os.SameFile(fi, s.owned) {
		os.Remove(s.path)
	}
	s.owned = nil
}

type socketListener struct {
	net.Listener
	socket *socketFile
}

// Close waits for the socket of an nc no peer reached to be judged; one in use goes once nc exits.
func (l *socketListener) Close() error {
	err := l.Listener.Close()
	l.socket.mu.Lock()
	last := l.socket.last
	l.socket.mu.Unlock()
	if last != nil && !last.seen.Load() {
		<-last.settled
	}
	return err
}
