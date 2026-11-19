package permuteproxy

import (
	"fmt"
)

// Engine builds chains into transports, clients and servers, borrowing Base and Upstream without ever closing them.
// A nil Base or Upstream resolves each call by its network name: the registered implementation, else the system for tcp, udp, unix and unixgram, else ErrUnsupported.
type Engine struct {
	Base     Network // reaches the endpoint
	Upstream Network // what servers reach their targets through
}

func (e Engine) network() Network {
	if e.Base != nil {
		return e.Base
	}
	return byName{}
}

func (e Engine) build(c Chain, r *resolved, from int) (Transport, error) {
	var t Transport = &bound{network: e.network(), stream: r.stream, packet: r.packet, address: c.Endpoint.Address}
	for i := len(c.Layers) - 1; i >= from; i-- {
		next, err := r.specs[i].Adapt(t, c.Layers[i].Options.clone())
		if err != nil {
			closeIf(t)
			return nil, fmt.Errorf("layer %q: %w", c.Layers[i].Scheme, err)
		}
		if next == nil {
			closeIf(t)
			return nil, fmt.Errorf("layer %q: Adapt returned nil", c.Layers[i].Scheme)
		}
		plane := r.planes[i]
		if i > 0 {
			// The layer above is never offered a plane without datagram boundaries.
			plane &^= r.specs[i].Lossy
		}
		t = pinned{TransportFuncs{Plane: plane, DialFunc: next.Dial, ListenFunc: next.Listen, ListenPacketFunc: next.ListenPacket}, next}
	}
	return t, nil
}

// Transport builds an adapter chain; with layers, the result's Close forwards to the outermost layer's own result.
func (e Engine) Transport(c Chain) (Transport, error) {
	r, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if len(r.specs) > 0 && r.specs[0].Kind == KindProxy {
		return nil, fmt.Errorf("layer %q: proxy needs Client or Server: %w", c.Layers[0].Scheme, ErrInvalidChain)
	}
	return e.build(c, r, 0)
}

func (c Chain) proxy() (*resolved, error) {
	r, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if len(r.specs) == 0 || r.specs[0].Kind != KindProxy {
		return nil, fmt.Errorf("outermost layer is not a proxy: %w", ErrInvalidChain)
	}
	return r, nil
}

// Client builds the client of a proxy chain's outermost layer; the result's Close forwards to the layer's own result.
func (e Engine) Client(c Chain) (Network, error) {
	r, err := c.proxy()
	if err != nil {
		return nil, err
	}
	scheme, spec := c.Layers[0].Scheme, r.specs[0]
	if spec.Client == nil {
		return nil, fmt.Errorf("layer %q: client: %w", scheme, ErrUnsupported)
	}
	inner, err := e.build(c, r, 1)
	if err != nil {
		return nil, err
	}
	n, err := spec.Client(inner, borrowed{e.network()}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	if n == nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: Client returned nil", scheme)
	}
	return restricted{network: n, plane: r.planes[0]}, nil
}

// Server builds the server of a proxy chain's outermost layer, which reaches its targets through Upstream.
func (e Engine) Server(c Chain) (Server, error) {
	r, err := c.proxy()
	if err != nil {
		return nil, err
	}
	scheme, spec := c.Layers[0].Scheme, r.specs[0]
	if spec.Server == nil {
		return nil, fmt.Errorf("layer %q: server: %w", scheme, ErrUnsupported)
	}
	inner, err := e.build(c, r, 1)
	if err != nil {
		return nil, err
	}
	upstream := e.Upstream
	if upstream == nil {
		upstream = byName{}
	}
	s, err := spec.Server(inner, borrowed{upstream}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	if s == nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: Server returned nil", scheme)
	}
	return s, nil
}
