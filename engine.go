package permuteproxy

import (
	"fmt"
)

// TransportEngine builds adapter chains into transports, borrowing Base without ever closing it.
type TransportEngine struct {
	Base Network // reaches the endpoint; nil resolves each call by network name: the registered implementation, else ErrUnsupported
}

// ClientEngine builds proxy chains into clients, borrowing Base and Local without ever closing them.
type ClientEngine struct {
	Base  Network // reaches the endpoint; nil resolves each call as a nil TransportEngine.Base does
	Local Network // what clients bind their own sockets through; nil resolves each call as a nil Base does
}

// ServerEngine builds proxy chains into servers, borrowing Base and Upstream without ever closing them.
type ServerEngine struct {
	Base     Network // reaches the endpoint; nil resolves each call as a nil TransportEngine.Base does
	Upstream Network // what servers reach their targets through; nil resolves each call as a nil Base does
}

// build stacks r's layers from the innermost out to from over base.
func build(base Network, r *resolved, from int) (Transport, error) {
	n, layered := orByName(base), len(r.layers) > 0
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

// Transport builds an adapter chain; with layers, the result's Close forwards to the outermost layer's own result.
func (e TransportEngine) Transport(c Chain) (Transport, error) {
	r, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if len(r.specs) > 0 && r.specs[0].isProxy() {
		return nil, fmt.Errorf("layer %q: proxy needs a ClientEngine or ServerEngine: %w", c.Layers[0].Scheme, ErrInvalidChain)
	}
	return build(e.Base, r, 0)
}

// below builds over base the Transport under c's outermost layer, which must be a proxy declaring side.
func below(base Network, c Chain, side string, declares func(LayerSpec) bool) (*resolved, Transport, error) {
	r, err := c.proxy()
	if err != nil {
		return nil, nil, err
	}
	if !declares(r.specs[0]) {
		return nil, nil, fmt.Errorf("layer %q: %s: %w", c.Layers[0].Scheme, side, ErrUnsupported)
	}
	inner, err := build(base, r, 1)
	if err != nil {
		return nil, nil, err
	}
	return r, inner, nil
}

// Client builds the client of a proxy chain's outermost layer, which binds its own sockets through Local; the result's Close forwards to the layer's own result. A bare command line, as cmd:ssh -W %h:%p jump, is itself the client: each tcp dial runs it with the target's host for %h and port for %p, "%%" writing a '%'.
func (e ClientEngine) Client(c Chain) (Network, error) {
	if c.templated() {
		return e.template(c)
	}
	r, inner, err := below(e.Base, c, "client", func(s LayerSpec) bool { return s.NewClient != nil })
	if err != nil {
		return nil, err
	}
	n, err := r.specs[0].client(inner, borrowed{orByName(e.Local)}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", c.Layers[0].Scheme, err)
	}
	return restricted{network: n, plane: r.planes[0]}, nil
}

// Server builds the server of a proxy chain's outermost layer, which reaches its targets through Upstream.
func (e ServerEngine) Server(c Chain) (Server, error) {
	r, inner, err := below(e.Base, c, "server", func(s LayerSpec) bool { return s.NewServer != nil })
	if err != nil {
		return nil, err
	}
	scheme, spec := c.Layers[0].Scheme, r.specs[0]
	if p := inner.Planes(); p&(spec.Requires|spec.Preserves) == 0 || p&spec.Requires != spec.Requires {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: serve over %v: %w", scheme, p, ErrUnsupported)
	}
	s, err := spec.server(inner, borrowed{orByName(e.Upstream)}, c.Layers[0].Options.clone())
	if err != nil {
		closeIf(inner)
		return nil, fmt.Errorf("layer %q: %w", scheme, err)
	}
	return s, nil
}
