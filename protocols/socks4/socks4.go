package socks4

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/wzshiming/socks4"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
)

const (
	KeyUsername = "username"
	// KeyPassword is accepted for socks4://u:p@ URIs and discarded: SOCKS4 has no password.
	KeyPassword = "password"
)

func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	username := opts[KeyUsername]
	return &permuteproxy.ClientFuncs{
		Dial: func(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
			dialer := &socks4.Dialer{
				Username:  username,
				IsResolve: true,
				Timeout:   time.Minute,
				ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return inner.Dial(ctx, permuteproxy.Stream)
				},
			}
			return dialer.DialContext(ctx, network, address)
		},
	}, nil
}

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	username := opts[KeyUsername]
	return &permuteproxy.ServerFuncs{
		Serve: func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
			owned := &listeners{listen: upstream.Listen}
			defer owned.Close()
			srv := socks4.NewServer()
			srv.Context = ctx
			srv.ProxyDial = upstream.DialContext
			srv.ProxyListenBind = owned.Listen
			srv.BytesPool = pool.Bytes
			if username != "" {
				srv.Authentication = socks4.UserAuth(username)
			}
			return srv.Serve(ln)
		},
	}, nil
}

// listeners owns the BIND listeners the library keeps open after its server stops.
type listeners struct {
	listen func(ctx context.Context, network, address string) (net.Listener, error)
	mu     sync.Mutex
	closed bool
	lns    []net.Listener
}

func (l *listeners) Listen(ctx context.Context, network, address string) (net.Listener, error) {
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

func (l *listeners) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for _, ln := range l.lns {
		ln.Close()
	}
	l.lns = nil
}
