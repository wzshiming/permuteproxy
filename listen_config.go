package permuteproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy/protocols"
)

// NewListenConfig returns a ListenConfig or ListenConn for the given uri.
// Depending on the type of scheme in the last kind there are different returns
// If the last kind is stream-like. will return ListenConn
// If the last kind is proxy, it will return Runner
func NewListenConfig(listenConfig ListenConfig, uri string) (ListenConn, Runner, error) {
	protocol, err := protocols.NewProtocol(uri)
	if err != nil {
		return nil, nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.ListenConfig == nil {
		return nil, nil, fmt.Errorf("scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
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

	var wrapper protocols.Wrapper
	for i := len(protocol.Wrappers) - 1; i >= 0; i-- {
		wrapper = protocol.Wrappers[i]
		handler = handle[wrapper.Scheme]

		if i == 0 && handler.ListenConfigWrapper == nil {
			break
		} else {
			if handler.ListenConfigWrapper == nil {
				return nil, nil, fmt.Errorf("scheme %q not supported: %w", wrapper.Scheme, protocols.ErrInvalidScheme)
			}
			metadata := wrapper.Metadata
			if metadata == nil {
				metadata = Metadata{}
			}
			listenConfig, err = handler.ListenConfigWrapper.ListenConfigWrap(listenConfig, metadata)
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
	if handler.NewRunner != nil {
		listener := newLazyListener(func() (Listener, error) {
			return listenConfig.Listen(context.Background(), ep.Network, ep.Address)
		})
		metadata := wrapper.Metadata
		if metadata == nil {
			metadata = Metadata{}
		}
		runner, err = handler.NewRunner.New(listener, metadata)
		if err != nil {
			return nil, nil, err
		}
	}
	return listenConn, runner, nil
}
