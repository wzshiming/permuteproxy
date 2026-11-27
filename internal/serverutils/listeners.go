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
	lns    map[*ownedListener]struct{}
}

func NewListeners(listen func(ctx context.Context, network, address string) (net.Listener, error)) *Listeners {
	return &Listeners{listen: listen, lns: map[*ownedListener]struct{}{}}
}

// Listen opens a listener that Close closes, unless its own Close came first and let go of it.
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
	owned := &ownedListener{Listener: ln, owner: l}
	l.lns[owned] = struct{}{}
	return owned, nil
}

func (l *Listeners) Close() {
	l.mu.Lock()
	l.closed = true
	lns := l.lns
	l.lns = nil
	l.mu.Unlock()
	for ln := range lns {
		ln.Close()
	}
}

func (l *Listeners) forget(ln *ownedListener) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.lns, ln)
}

// ownedListener leaves its Listeners once closed, so a server's finished BINDs do not pile up.
type ownedListener struct {
	net.Listener
	owner *Listeners
	once  sync.Once
	err   error
}

func (o *ownedListener) Close() error {
	o.once.Do(func() {
		o.owner.forget(o)
		o.err = o.Listener.Close()
	})
	return o.err
}
