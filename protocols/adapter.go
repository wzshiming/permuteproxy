package protocols

import (
	"context"
	"fmt"
	"net"
)

var ErrNetClosing = fmt.Errorf("use of closed network connection")

type (
	Listener = net.Listener
	Conn     = net.Conn
	Addr     = net.Addr
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
	ListenConfigWrap(listenConfig ListenConfig) (ListenConfig, error)
}

// ListenConfigWrapperFunc type is an adapter for ListenConfigWrapper.
type ListenConfigWrapperFunc func(listenConfig ListenConfig) (ListenConfig, error)

// ListenConfigWrap calls l(listenConfig)
func (l ListenConfigWrapperFunc) ListenConfigWrap(listenConfig ListenConfig) (ListenConfig, error) {
	return l(listenConfig)
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
	DialerWrap(dialer Dialer) (Dialer, error)
}

// DialerWrapperFunc type is an adapter for DialerWrapper.
type DialerWrapperFunc func(dialer Dialer) (Dialer, error)

// DialerWrap calls d(dialer)
func (d DialerWrapperFunc) DialerWrap(dialer Dialer) (Dialer, error) {
	return d(dialer)
}

// ServeConn wraps a net.Conn with additional options.
type ServeConn interface {
	ServeConn(ctx context.Context, conn Conn)
}

// ServeConnFunc type is an adapter for ServeConn.
type ServeConnFunc func(ctx context.Context, conn Conn)

// ServeConn calls s(conn)
func (s ServeConnFunc) ServeConn(ctx context.Context, conn Conn) {
	s(ctx, conn)
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

type Forwarder interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (Conn, Addr, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() Addr
}

// ListenForward wraps a net.Conn with additional options.
type ListenForward interface {
	Listen(ctx context.Context) (Forwarder, error)
}

// ListenForwardFunc type is an adapter for ListenConn.
type ListenForwardFunc func(ctx context.Context) (Forwarder, error)

// Listen calls d()
func (d ListenForwardFunc) Listen(ctx context.Context) (Forwarder, error) {
	return d(ctx)
}

type ConnWrapperFunc func(conn Conn) (Conn, error)

type Runner interface {
	Run(ctx context.Context) error
	Close() error
}

type NewRunnerFunc func(listener Listener) Runner

type NewDialerFunc func(dialer Dialer) (Dialer, error)
