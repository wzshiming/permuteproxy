package serverutils

import (
	"context"
	"net"
	"sync"
)

// Listeners owns the BIND listeners a socks library keeps open after its server stops.
type Listeners struct {
	listen func(ctx context.Context, network, address string) (net.Listener, error)
	mu     sync.Mutex
	closed bool
	lns    []net.Listener
}

func NewListeners(listen func(ctx context.Context, network, address string) (net.Listener, error)) *Listeners {
	return &Listeners{listen: listen}
}

func (l *Listeners) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	ln, err := l.listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		ln.Close()
		return nil, net.ErrClosed
	}
	l.lns = append(l.lns, ln)
	return ln, nil
}

func (l *Listeners) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for _, ln := range l.lns {
		ln.Close()
	}
	l.lns = nil
}
