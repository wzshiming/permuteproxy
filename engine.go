package permuteproxy

import (
	"fmt"
)

// Engine builds chains into transports, clients and servers, borrowing Base and Upstream without ever closing them.
type Engine struct {
	Base     Network // reaches the endpoint; nil resolves each call by network name: the registered implementation, else the system for tcp, udp, unix and unixgram, else ErrUnsupported
	Upstream Network // what servers reach their targets through; nil resolves each call as a nil Base does
}

func (e Engine) network() Network {
	if e.Base != nil {
		return e.Base
	}
	return byName{}
}

func (e Engine) build(r *resolved, from int) (Transport, error) {
	n, layered := e.network(), len(r.layers) > 0
	dial := bind(n, r.stream, r.packet, r.dial, layered)
	// The layers get what the carrier offers once a lossy network took its datagrams, not what resolve assumed.
	r.offer(dial.Planes())
	var t Transport = dial
	if r.listen != r.dial {
		t = split(t, bind(n, r.stream, r.packet, r.listen, layered))
	}
	t, err := r.stack(t, r.own, len(r.layers))
	if err != nil {
		return nil, err
	}
	if a := r.around; a != nil {
		// The split admits only the plane the expression provides, so the declared name serves either.
		t = split(t, bind(n, a.Network, a.Network, a.Address, r.own > 0))
	}
	return r.stack(t, from, r.own)
}

// bind binds n to address on the networks named per plane, layered when layers sit above it.
func bind(n Network, stream, packet, address string, layered bool) *bound {
	b := &bound{network: n, stream: stream, packet: packet, address: address}
	// A layer is never offered a datagram plane that its network reports lossy.
	if layered && b.packet != "" && isLossy(b.network, b.packet) {
		b.packet = ""
	}
	return b
}

// stack builds layers hi-1 out to lo over t, closing what it holds when a layer fails.
func (r *resolved) stack(t Transport, lo, hi int) (Transport, error) {
	for i := hi - 1; i >= lo; i-- {
		next, err := r.specs[i].adapt(t, r.layers[i].Options.clone())
		if err != nil {
			closeIf(t)
			return nil, fmt.Errorf("layer %q: %w", r.layers[i].Scheme, err)
		}
		t = pinned{TransportFuncs{Plane: r.planes[i], DialFunc: next.Dial, ListenFunc: next.Listen, ListenPacketFunc: next.ListenPacket}, next}
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
	return e.build(r, 0)
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
	if spec.NewClient == nil {
		return nil, fmt.Errorf("layer %q: client: %w", scheme, ErrUnsupported)
	}
	inner, err := e.build(r, 1)
	if err != nil {
		return nil, err
	}
	n, err := spec.client(inner, borrowed{e.network()}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
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
	if spec.NewServer == nil {
		return nil, fmt.Errorf("layer %q: server: %w", scheme, ErrUnsupported)
	}
	inner, err := e.build(r, 1)
	if err != nil {
		return nil, err
	}
	if p := inner.Planes(); p&(spec.Requires|spec.Preserves) == 0 || p&spec.Requires != spec.Requires {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: serve over %v: %w", scheme, p, ErrUnsupported)
	}
	upstream := e.Upstream
	if upstream == nil {
		upstream = byName{}
	}
	s, err := spec.server(inner, borrowed{upstream}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	return s, nil
}
