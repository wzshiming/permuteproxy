package netutils

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wzshiming/cmux"
)

func NewCommandDialContext(ctx context.Context, commandDialer CommandDialer, localAddr, remoteAddr net.Addr, proxy []string) (net.Conn, error) {
	conn, err := commandDialer.CommandDialContext(ctx, proxy[0], proxy[1:]...)
	if err != nil {
		return nil, err
	}

	conn = ConnWithAddr(conn, localAddr, remoteAddr)
	return conn, nil
}

func NewCommandListener(ctx context.Context, commandDialer CommandDialer, localAddr net.Addr, remoteAddr net.Addr, proxy []string) (net.Listener, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &listener{
		ctx:           ctx,
		cancel:        cancel,
		commandDialer: commandDialer,
		localAddr:     localAddr,
		remoteAddr:    remoteAddr,
		proxy:         proxy,
	}, nil
}

type listener struct {
	ctx           context.Context
	cancel        context.CancelFunc
	commandDialer CommandDialer
	proxy         []string
	localAddr     net.Addr
	remoteAddr    net.Addr
	isClose       uint32
	mux           sync.Mutex
}

func (l *listener) Accept() (net.Conn, error) {
	l.mux.Lock()
	defer l.mux.Unlock()
	if atomic.LoadUint32(&l.isClose) == 1 {
		return nil, ErrClosedConn
	}

	connCh := make(chan net.Conn)
	errCh := make(chan error)
	go func() {
		n, err := NewCommandDialContext(l.ctx, l.commandDialer, l.localAddr, l.remoteAddr, l.proxy)
		if err != nil {
			errCh <- err
			return
		}

		// Because there is no way to tell if there is a connection coming in from the command line,
		// the next listen can only be performed if the data is read or closed
		var tmp [1]byte
		_, err = n.Read(tmp[:])
		if err != nil {
			errCh <- err
			return
		}
		n = cmux.UnreadConn(n, tmp[:])
		connCh <- n
	}()

	select {
	case <-l.ctx.Done():
		return nil, ErrClosedConn
	case err := <-errCh:
		return nil, err
	case n := <-connCh:
		return n, nil
	}
}

func (l *listener) Close() error {
	atomic.StoreUint32(&l.isClose, 1)
	l.cancel()
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.localAddr
}
