package permuteproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy/protocols"
)

// NewListenConn returns a new ListenConn.
// If the last kind is stream-like. will return ListenConn
func (p *Proxy) NewListenConn(uri string) (ListenConn, error) {
	protocol, err := protocols.NewProtocol(uri)
	if err != nil {
		return nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.ListenConfig == nil {
		return nil, fmt.Errorf("first scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	listenConfig := p.ListenConfig
	if listenConfig == nil {
		l := handler.ListenConfig
		listenConfig = ListenConfigFunc(func(ctx context.Context, network, address string) (Listener, error) {
			ctx = withContext(ctx, p)
			return l.Listen(ctx, network, address)
		})
	} else {
		l := listenConfig
		listenConfig = ListenConfigFunc(func(ctx context.Context, network, address string) (Listener, error) {
			ctx = withContext(ctx, p)
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
				return nil, fmt.Errorf("%d scheme %q not supported: %w", i, wrapper.Scheme, protocols.ErrInvalidScheme)
			}
			metadata := wrapper.Metadata
			if metadata == nil {
				metadata = Metadata{}
			}

			ctx := withContext(context.Background(), p.withListenConfig(listenConfig))
			listenConfig, err = handler.ListenConfigWrapper.ListenConfigWrap(ctx, metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap scheme %q: %w", wrapper.Scheme, err)
			}
		}
	}

	if handler.ListenConfigWrapper != nil && handler.NewRunner != nil {
		return nil, fmt.Errorf("last scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	listenConn := ListenConnFunc(func(ctx context.Context) (net.Listener, error) {
		ctx = withContext(ctx, p)
		return listenConfig.Listen(ctx, ep.Network, ep.Address)
	})

	return listenConn, nil
}

// NewRunner returns a new Runner.
// If the last kind is proxy, it will return Runner
func (p *Proxy) NewRunner(uri string) (Runner, error) {
	protocol, err := protocols.NewProtocol(uri)
	if err != nil {
		return nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.ListenConfig == nil {
		return nil, fmt.Errorf("first scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	listenConfig := p.ListenConfig
	if listenConfig == nil {
		l := handler.ListenConfig
		listenConfig = ListenConfigFunc(func(ctx context.Context, network, address string) (Listener, error) {
			ctx = withContext(ctx, p)
			return l.Listen(ctx, network, address)
		})
	} else {
		l := listenConfig
		listenConfig = ListenConfigFunc(func(ctx context.Context, network, address string) (Listener, error) {
			ctx = withContext(ctx, p)
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
				return nil, fmt.Errorf("%d scheme %q not supported: %w", i, wrapper.Scheme, protocols.ErrInvalidScheme)
			}
			metadata := wrapper.Metadata
			if metadata == nil {
				metadata = Metadata{}
			}

			ctx := withContext(context.Background(), p.withListenConfig(listenConfig))
			listenConfig, err = handler.ListenConfigWrapper.ListenConfigWrap(ctx, metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap scheme %q: %w", wrapper.Scheme, err)
			}
		}
	}

	if handler.NewRunner == nil {
		return nil, fmt.Errorf("last scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	ctx := context.Background()
	listener := newLazyListener(func() (Listener, error) {
		return listenConfig.Listen(ctx, ep.Network, ep.Address)
	})
	metadata := wrapper.Metadata
	if metadata == nil {
		metadata = Metadata{}
	}
	runner, err := handler.NewRunner.New(listener, metadata)
	if err != nil {
		return nil, err
	}
	return runner, nil
}
