package protocols

import (
	"context"
	"fmt"
	"net"
)

type Handle struct {
	Dialer              Dialer
	DialerWrapper       DialerWrapper
	ListenConfig        ListenConfig
	ListenConfigWrapper ListenConfigWrapper

	NewDialer     NewDialerFunc
	NewRunnerFunc NewRunnerFunc
}

var handle = map[string]Handle{}

func RegisterHandle(scheme string, h Handle) {
	handle[scheme] = h
}

// NewDialer returns a Dialer or DialConn for the given uri.
// Depending on the type of scheme in the last kind there are different returns
// If the last kind is stream-like. will return DialConn
// If the last kind is proxy, it will return Dialer
func NewDialer(dialer Dialer, uri string) (Dialer, DialConn, error) {
	protocol, err := NewProtocol(uri)
	if err != nil {
		return nil, nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.Dialer == nil {
		return nil, nil, fmt.Errorf("scheme %q not supported: %w", ep.Network, ErrInvalidScheme)
	}

	if dialer == nil {
		d := handler.Dialer
		dialer = DialerFunc(func(ctx context.Context, network, address string) (Conn, error) {
			return d.DialContext(ctx, ep.Network, ep.Address)
		})
	} else {
		d := dialer
		dialer = DialerFunc(func(ctx context.Context, network, address string) (Conn, error) {
			return d.DialContext(ctx, ep.Network, ep.Address)
		})
	}

	for i := len(protocol.Wrappers) - 1; i >= 0; i-- {
		wrapper := protocol.Wrappers[i]
		handler = handle[wrapper.Scheme]

		if i == 0 && handler.DialerWrapper == nil {
			break
		} else {
			if handler.DialerWrapper == nil {
				return nil, nil, fmt.Errorf("scheme %q not supported: %w", wrapper.Scheme, ErrInvalidScheme)
			}
			dialer, err = handler.DialerWrapper.DialerWrap(dialer)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to wrap scheme %q: %w", wrapper.Scheme, err)
			}
		}
	}
	var dialConn DialConn
	if handler.DialerWrapper == nil {
		dialConn = DialConnFunc(func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, ep.Network, ep.Address)
		})
	}
	if handler.NewDialer != nil {
		dialer, err = handler.NewDialer(dialer)
		if err != nil {
			return nil, nil, err
		}
	}

	return dialer, dialConn, nil
}

// NewListenConfig returns a ListenConfig or ListenConn for the given uri.
// Depending on the type of scheme in the last kind there are different returns
// If the last kind is stream-like. will return ListenConn
// If the last kind is proxy, it will return Runner
func NewListenConfig(listenConfig ListenConfig, uri string) (ListenConn, Runner, error) {
	protocol, err := NewProtocol(uri)
	if err != nil {
		return nil, nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.ListenConfig == nil {
		return nil, nil, fmt.Errorf("scheme %q not supported: %w", ep.Network, ErrInvalidScheme)
	}

	if listenConfig == nil {
		l := handler.ListenConfig
		listenConfig = ListenConfigFunc(func(ctx context.Context, network, address string) (Listener, error) {
			return l.Listen(ctx, network, address)
		})
	} else {
		l := listenConfig
		listenConfig = ListenConfigFunc(func(ctx context.Context, network, address string) (Listener, error) {
			return l.Listen(ctx, network, address)
		})
	}
	for i := len(protocol.Wrappers) - 1; i >= 0; i-- {
		wrapper := protocol.Wrappers[i]
		handler = handle[wrapper.Scheme]

		if i == 0 && handler.ListenConfigWrapper == nil {
			break
		} else {
			if handler.ListenConfigWrapper == nil {
				return nil, nil, fmt.Errorf("scheme %q not supported: %w", wrapper.Scheme, ErrInvalidScheme)
			}
			listenConfig, err = handler.ListenConfigWrapper.ListenConfigWrap(listenConfig)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to wrap scheme %q: %w", wrapper.Scheme, err)
			}
		}
	}

	var listenConn ListenConn
	if handler.ListenConfigWrapper == nil {
		listenConn = ListenConnFunc(func(ctx context.Context) (net.Listener, error) {
			return listenConfig.Listen(ctx, ep.Network, ep.Address)
		})
	}

	var runner Runner
	if handler.NewRunnerFunc != nil {
		listener := NewLazyListener(func() (Listener, error) {
			return listenConfig.Listen(context.Background(), ep.Network, ep.Address)
		})
		runner = handler.NewRunnerFunc(listener)
	}
	return listenConn, runner, nil
}
