package netcat

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
	"github.com/wzshiming/permuteproxy/protocols/command"
)

// Runner is a command.Runner that also listens on cmd-nc-unix, where each connection is an nc -Ul
// of its own and the socket file an nc leaves behind is removed, and binds cmd-nc-udp and
// cmd-nc-unixgram as one nc -u -l, which serves a single peer. A Base given to an engine does either only if it is one.
type Runner struct{ *command.Runner }

// Network is the Runner over command.Network, the registered implementation of cmd-nc-unix, cmd-nc-udp and cmd-nc-unixgram.
var Network = Runner{command.Network}

// Listen removes the socket file an nc leaves behind only when a peer sent a byte through it,
// the one proof that nc bound the path, and it is still the inode recorded then; any other file
// there stays, even one an idle or killed nc made, as it may as well be a competitor's.
func (l Runner) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if network != "cmd-nc-unix" {
		return l.Runner.Listen(ctx, network, address)
	}
	// The path enters an nc command line, so it must be one the network's declaration accepts.
	if err := (permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: network, Address: address}}).Validate(); err != nil {
		return nil, err
	}
	line := strings.ReplaceAll(ListenUnix, "%h", cmdutils.Quote([]string{address}))
	socket := &socketFile{path: address}
	return l.Runner.ListenCommand(ctx, line, func(start command.CommandFunc) command.CommandFunc {
		return func(ctx context.Context, name string, args ...string) (net.Conn, error) {
			socket.before()
			// Debian's nc unlinks whatever the path holds before it binds, so it only gets a free path.
			if _, err := os.Lstat(address); err == nil {
				return nil, &os.PathError{Op: "listen", Path: address, Err: os.ErrExist}
			}
			conn, err := start(ctx, name, args...)
			if err != nil {
				return nil, err
			}
			return socket.track(conn), nil
		}
	})
}

// ListenPacket binds cmd-nc-udp and cmd-nc-unixgram at address as one nc -u -l, a socket for the
// single peer nc serves. The socket file of cmd-nc-unixgram is left behind, as nothing proves it is nc's.
func (l Runner) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	template, ok := map[string]string{"cmd-nc-udp": ListenUDP, "cmd-nc-unixgram": ListenUnixgram}[network]
	if !ok {
		return l.Runner.ListenPacket(ctx, network, address)
	}
	return listenPacket(ctx, l.Runner, cmdutils.Template(template), network, address)
}

type socketFile struct {
	path string
	mu   sync.Mutex
	last *served
}

// served is one nc: the first byte a peer sends through it claims the socket, which is removed
// once nc has exited, or on Close when the command exposes no process.
type served struct {
	net.Conn
	socket  *socketFile
	seen    atomic.Bool
	settled chan struct{}
	// owned and done are guarded by socket.mu.
	owned os.FileInfo
	done  bool
}

func (c *served) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.seen.CompareAndSwap(false, true) {
		c.claim()
	}
	return n, err
}

// claim records the socket's inode unless nc is already gone, so a file placed since is not taken for ours.
func (c *served) claim() {
	c.socket.mu.Lock()
	defer c.socket.mu.Unlock()
	if c.done {
		return
	}
	if fi, err := os.Lstat(c.socket.path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		c.owned = fi
	}
}

// settle removes the claimed socket if it is still the recorded inode and ends claiming.
func (c *served) settle() {
	c.socket.mu.Lock()
	defer c.socket.mu.Unlock()
	if c.done {
		return
	}
	c.done = true
	if c.owned != nil {
		if fi, err := os.Lstat(c.socket.path); err == nil && os.SameFile(fi, c.owned) {
			os.Remove(c.socket.path)
		}
	}
	close(c.settled)
}

// track settles each nc once it has exited, or on Close when it exposes no process.
func (s *socketFile) track(conn net.Conn) net.Conn {
	sc := &served{Conn: conn, socket: s, settled: make(chan struct{})}
	s.mu.Lock()
	s.last = sc
	s.mu.Unlock()
	p, ok := conn.(netutils.Process)
	if !ok {
		return netutils.ConnWithCloser(sc, func() error {
			err := sc.Conn.Close()
			sc.settle()
			return err
		})
	}
	go func() {
		<-p.Done()
		sc.settle()
	}()
	return netutils.ConnWithProcess(sc, conn)
}

// before waits for the previous nc to be settled so its socket is gone before the next one binds.
func (s *socketFile) before() {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last != nil {
		<-last.settled
	}
}
