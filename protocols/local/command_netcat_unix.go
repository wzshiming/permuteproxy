package local

import (
	"context"
	"net"
	"os"
	"sync"

	"github.com/wzshiming/permuteproxy/internal/cmdutils"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

func (l *Local) dialNetcatUnix(ctx context.Context, address string) (net.Conn, error) {
	return cmdutils.DialContext(ctx, l.Command, localAddr, netutils.NewNetAddr("cmd", "nc -U "+address), []string{"nc", "-U", address})
}

// listenNetcatUnix removes the socket file each nc leaves behind before the next one binds, but
// only the file a connection was accepted through; any other file at the path makes nc fail.
func (l *Local) listenNetcatUnix(ctx context.Context, address string) (net.Listener, error) {
	socket := &socketFile{path: address}
	dial := func(ctx context.Context, name string, args ...string) (net.Conn, error) {
		socket.removeOwned()
		return l.Command(ctx, name, args...)
	}
	ln, err := cmdutils.Listen(ctx, dial, localAddr, netutils.NewNetAddr("cmd", "nc -Ul "+address), []string{"nc", "-Ul", address})
	if err != nil {
		return nil, err
	}
	return &socketListener{Listener: ln, socket: socket}, nil
}

type socketFile struct {
	path  string
	mu    sync.Mutex
	owned os.FileInfo
}

// claim records the socket file once a peer has connected through it, so nc must have created it.
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

func (l *socketListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.socket.claim()
	}
	return conn, err
}
