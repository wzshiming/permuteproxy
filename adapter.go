package permuteproxy

import (
	"context"
	"net"
	"net/url"
)

type (
	Listener   = net.Listener
	PacketConn = net.PacketConn
	Conn       = net.Conn
	Addr       = net.Addr
	Metadata   = url.Values
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
	ListenConfigWrap(ctx context.Context, metadata Metadata) (ListenConfig, error)
}

// ListenConfigWrapperFunc type is an adapter for ListenConfigWrapper.
type ListenConfigWrapperFunc func(ctx context.Context, metadata Metadata) (ListenConfig, error)

// ListenConfigWrap calls l(listenConfig)
func (l ListenConfigWrapperFunc) ListenConfigWrap(ctx context.Context, metadata Metadata) (ListenConfig, error) {
	return l(ctx, metadata)
}

// ListenPacketConfig contains options for listening to an address.
type ListenPacketConfig interface {
	ListenPacket(ctx context.Context, network, address string) (PacketConn, error)
}

// ListenPacketConfigFunc type is an adapter for ListenPacketConfig.
type ListenPacketConfigFunc func(ctx context.Context, network, address string) (PacketConn, error)

// ListenPacket calls b(ctx, network, address)
func (l ListenPacketConfigFunc) ListenPacket(ctx context.Context, network, address string) (PacketConn, error) {
	return l(ctx, network, address)
}

// ListenPacketConfigWrapper wraps a ListenPacketConfig with additional options.
type ListenPacketConfigWrapper interface {
	ListenPacketConfigWrap(ctx context.Context, metadata Metadata) (ListenPacketConfig, error)
}

// ListenPacketConfigWrapperFunc type is an adapter for ListenPacketConfigWrapper.
type ListenPacketConfigWrapperFunc func(lctx context.Context, metadata Metadata) (ListenPacketConfig, error)

// ListenPacketConfigWrap calls l(listenPacketConfig)
func (l ListenPacketConfigWrapperFunc) ListenPacketConfigWrap(ctx context.Context, metadata Metadata) (ListenPacketConfig, error) {
	return l(ctx, metadata)
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
	DialerWrap(ctx context.Context, metadata Metadata) (Dialer, error)
}

// DialerWrapperFunc type is an adapter for DialerWrapper.
type DialerWrapperFunc func(ctx context.Context, metadata Metadata) (Dialer, error)

// DialerWrap calls d(dialer)
func (d DialerWrapperFunc) DialerWrap(ctx context.Context, metadata Metadata) (Dialer, error) {
	return d(ctx, metadata)
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

// CommandDialer contains options for connecting to an address with command.
type CommandDialer interface {
	CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error)
}

// CommandDialFunc type is an adapter for Dialer with command.
type CommandDialFunc func(ctx context.Context, name string, args ...string) (net.Conn, error)

// CommandDialContext calls d(ctx, name, args...)
func (d CommandDialFunc) CommandDialContext(ctx context.Context, name string, args ...string) (net.Conn, error) {
	return d(ctx, name, args...)
}

// CommandDialerWrapper wraps a CommandDialer with additional options.
type CommandDialerWrapper interface {
	CommandDialerWrap(ctx context.Context, metadata Metadata) (CommandDialer, error)
}

// CommandDialerWrapperFunc type is an adapter for CommandDialerWrapper.
type CommandDialerWrapperFunc func(ctx context.Context, metadata Metadata) (CommandDialer, error)

// CommandDialerWrap calls d(commandDialer)
func (d CommandDialerWrapperFunc) CommandDialerWrap(ctx context.Context, metadata Metadata) (CommandDialer, error) {
	return d(ctx, metadata)
}

// NewRunner creates a new Runner.
type NewRunner interface {
	New(listener Listener, metadata Metadata) (Runner, error)
}

// Runner is a runner.
type Runner interface {
	Run(ctx context.Context) error
	Close() error
}

// NewRunnerFunc type is an adapter for NewRunner.
type NewRunnerFunc func(listener Listener, metadata Metadata) (Runner, error)

// New calls n(listener, metadata)
func (n NewRunnerFunc) New(listener Listener, metadata Metadata) (Runner, error) {
	return n(listener, metadata)
}
