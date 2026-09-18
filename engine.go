package permuteproxy

import (
	"fmt"
)

// Engine builds chains; a nil Base uses the endpoint network's registered implementation or the
// system net package, a nil Upstream gives servers direct system networking.
// Transport and Client results implement io.Closer, forwarding to the layer's own result; Base and
// Upstream are borrowed and never closed through them.
type Engine struct {
	Base     Network
	Upstream Network
}

func (e Engine) network(r *resolved) Network {
	if e.Base != nil {
		return e.Base
	}
	if r.impl != nil {
		return r.impl
	}
	return native
}

func (e Engine) build(c Chain, r *resolved, from int) (Transport, error) {
	var t Transport = &bound{network: e.network(r), stream: r.stream, packet: r.packet, address: c.Endpoint.Address}
	for i := len(c.Layers) - 1; i >= from; i-- {
		next, err := r.specs[i].Adapt(t, c.Layers[i].Options.clone())
		if err != nil {
			return nil, fmt.Errorf("layer %q: %w", c.Layers[i].Scheme, err)
		}
		if next == nil {
			return nil, fmt.Errorf("layer %q: Adapt returned nil", c.Layers[i].Scheme)
		}
		t = pinned{TransportFuncs{Plane: r.planes[i], DialFunc: next.Dial, ListenFunc: next.Listen, ListenPacketFunc: next.ListenPacket}, next}
	}
	return t, nil
}

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
	n, err := spec.Client(inner, borrowed{e.network(r)}, c.Layers[0].Options.clone())
	if err != nil {
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	if n == nil {
		return nil, fmt.Errorf("layer %q: Client returned nil", scheme)
	}
	return restricted{network: n, plane: r.planes[0]}, nil
}

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
		upstream = native
	}
	s, err := spec.Server(inner, borrowed{upstream}, c.Layers[0].Options.clone())
	if err != nil {
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	if s == nil {
		return nil, fmt.Errorf("layer %q: Server returned nil", scheme)
	}
	return s, nil
}
