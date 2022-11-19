package permuteproxy

import (
	"context"
	"net"
	"net/url"
)

type (
	Listener = net.Listener
	Conn     = net.Conn
	Addr     = net.Addr
	Metadata = url.Values
)

// ListenConfig contains options for listening to an address.
type ListenConfig interface {
	Listen(ctx context.Context, network, address string) (Listener, error)
}

// ListenConfigFunc type is an adapter for ListenConfig.
type ListenConfigFunc func(ctx context.Context, network, address string) (Listener, error)

// Listen calls b(ctx, network, address)
func (l ListenConfigFunc) Listen(ctx context.Context, network, address string) (Listener, error) {
	return l(ctx, network, address)
}

// ListenConfigWrapper wraps a ListenConfig with additional options.
type ListenConfigWrapper interface {
	ListenConfigWrap(listenConfig ListenConfig, metadata Metadata) (ListenConfig, error)
}

// ListenConfigWrapperFunc type is an adapter for ListenConfigWrapper.
type ListenConfigWrapperFunc func(listenConfig ListenConfig, metadata Metadata) (ListenConfig, error)

// ListenConfigWrap calls l(listenConfig)
func (l ListenConfigWrapperFunc) ListenConfigWrap(listenConfig ListenConfig, metadata Metadata) (ListenConfig, error) {
	return l(listenConfig, metadata)
}

// Dialer contains options for connecting to an address.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (Conn, error)
}

// DialerFunc type is an adapter for Dialer.
type DialerFunc func(ctx context.Context, network, address string) (Conn, error)

// DialContext calls d(ctx, network, address)
func (d DialerFunc) DialContext(ctx context.Context, network, address string) (Conn, error) {
	return d(ctx, network, address)
}

// DialerWrapper wraps a Dialer with additional options.
type DialerWrapper interface {
	DialerWrap(dialer Dialer, metadata Metadata) (Dialer, error)
}

// DialerWrapperFunc type is an adapter for DialerWrapper.
type DialerWrapperFunc func(dialer Dialer, metadata Metadata) (Dialer, error)

// DialerWrap calls d(dialer)
func (d DialerWrapperFunc) DialerWrap(dialer Dialer, metadata Metadata) (Dialer, error) {
	return d(dialer, metadata)
}

// DialConn wraps a net.Conn with additional options.
type DialConn interface {
	Dial(ctx context.Context) (Conn, error)
}

// DialConnFunc type is an adapter for DialConn.
type DialConnFunc func(ctx context.Context) (Conn, error)

// Dial calls d()
func (d DialConnFunc) Dial(ctx context.Context) (Conn, error) {
	return d(ctx)
}

// ListenConn wraps a net.Conn with additional options.
type ListenConn interface {
	Listen(ctx context.Context) (Listener, error)
}

// ListenConnFunc type is an adapter for ListenConn.
type ListenConnFunc func(ctx context.Context) (Listener, error)

// Listen calls d()
func (d ListenConnFunc) Listen(ctx context.Context) (Listener, error) {
	return d(ctx)
}

type NewRunner interface {
	New(listener Listener, metadata Metadata) (Runner, error)
}

type Runner interface {
	Run(ctx context.Context) error
	Close() error
}

type NewRunnerFunc func(listener Listener, metadata Metadata) (Runner, error)

func (n NewRunnerFunc) New(listener Listener, metadata Metadata) (Runner, error) {
	return n(listener, metadata)
}
