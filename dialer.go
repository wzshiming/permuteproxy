package permuteproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy/protocols"
)

// NewDialer returns a Dialer or DialConn for the given uri.
// Depending on the type of scheme in the last kind there are different returns
// If the last kind is stream-like. will return DialConn
// If the last kind is proxy, it will return Dialer
func NewDialer(dialer Dialer, uri string) (Dialer, DialConn, error) {
	protocol, err := protocols.NewProtocol(uri)
	if err != nil {
		return nil, nil, err
	}

	ep := protocol.Endpoint

	handler := handle[ep.Network]
	if handler.Dialer == nil {
		return nil, nil, fmt.Errorf("scheme %q not supported: %w", ep.Network, protocols.ErrInvalidScheme)
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

	var wrapper protocols.Wrapper
	for i := len(protocol.Wrappers) - 1; i >= 0; i-- {
		wrapper = protocol.Wrappers[i]
		handler = handle[wrapper.Scheme]

		if i == 0 && handler.DialerWrapper == nil {
			break
		} else {
			if handler.DialerWrapper == nil {
				return nil, nil, fmt.Errorf("scheme %q not supported: %w", wrapper.Scheme, protocols.ErrInvalidScheme)
			}
			metadata := wrapper.Metadata
			if metadata == nil {
				metadata = Metadata{}
			}
			dialer, err = handler.DialerWrapper.DialerWrap(dialer, metadata)
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

	return dialer, dialConn, nil
}
