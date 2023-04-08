package permuteproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy/protocols"
)

// NewDialer returns a Dialer from the uri
// If the last kind is proxy, it will return Dialer
func (p *Proxy) NewDialer(uri string) (Dialer, error) {
	protocol, err := protocols.NewProtocol(uri)
	if err != nil {
		return nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.Dialer == nil {
		return nil, fmt.Errorf("first scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	dialer := p.Dialer
	if dialer == nil {
		d := handler.Dialer
		dialer = DialerFunc(func(ctx context.Context, network, address string) (Conn, error) {
			ctx = withContext(ctx, p)
			return d.DialContext(ctx, ep.Network, ep.Address)
		})
	} else {
		d := dialer
		dialer = DialerFunc(func(ctx context.Context, network, address string) (Conn, error) {
			ctx = withContext(ctx, p)
			return d.DialContext(ctx, ep.Network, ep.Address)
		})
	}

	var wrapper protocols.Wrapper
	for i := len(protocol.Wrappers) - 1; i >= 0; i-- {
		wrapper = protocol.Wrappers[i]
		handler = handle[wrapper.Scheme]

		if i == 0 && handler.DialerWrapper == nil {
			break
		} else {
			if handler.DialerWrapper == nil {
				return nil, fmt.Errorf("%d scheme %q not supported: %w", i, wrapper.Scheme, protocols.ErrInvalidScheme)
			}
			metadata := wrapper.Metadata
			if metadata == nil {
				metadata = Metadata{}
			}

			ctx := withContext(context.Background(), p.withDialer(dialer))
			dialer, err = handler.DialerWrapper.DialerWrap(ctx, metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap scheme %q: %w", wrapper.Scheme, err)
			}
		}
	}

	if handler.DialerWrapper == nil {
		return nil, fmt.Errorf("last scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	return dialer, nil
}

// NewDialConn returns a DialConn for the given uri.
// If the last kind is stream-like. will return DialConn
func (p *Proxy) NewDialConn(uri string) (DialConn, error) {
	protocol, err := protocols.NewProtocol(uri)
	if err != nil {
		return nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.Dialer == nil {
		return nil, fmt.Errorf("first scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	dialer := p.Dialer
	if dialer == nil {
		d := handler.Dialer
		dialer = DialerFunc(func(ctx context.Context, network, address string) (Conn, error) {
			ctx = withContext(ctx, p)
			return d.DialContext(ctx, ep.Network, ep.Address)
		})
	} else {
		d := dialer
		dialer = DialerFunc(func(ctx context.Context, network, address string) (Conn, error) {
			ctx = withContext(ctx, p)
			return d.DialContext(ctx, ep.Network, ep.Address)
		})
	}

	var wrapper protocols.Wrapper
	for i := len(protocol.Wrappers) - 1; i >= 0; i-- {
		wrapper = protocol.Wrappers[i]
		handler = handle[wrapper.Scheme]

		if i == 0 && handler.DialerWrapper == nil {
			break
		} else {
			if handler.DialerWrapper == nil {
				return nil, fmt.Errorf("%d scheme %q not supported: %w", i, wrapper.Scheme, protocols.ErrInvalidScheme)
			}
			metadata := wrapper.Metadata
			if metadata == nil {
				metadata = Metadata{}
			}

			ctx := withContext(context.Background(), p.withDialer(dialer))
			dialer, err = handler.DialerWrapper.DialerWrap(ctx, metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap scheme %q: %w", wrapper.Scheme, err)
			}
		}
	}

	if handler.DialerWrapper != nil {
		return nil, fmt.Errorf("last scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
	}

	dialConn := DialConnFunc(func(ctx context.Context) (net.Conn, error) {
		ctx = withContext(ctx, p)
		return dialer.DialContext(ctx, ep.Network, ep.Address)
	})

	return dialConn, nil
}
