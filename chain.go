package permuteproxy

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

// ErrInvalidChain is returned, before any I/O, for a chain or declaration the root package cannot build.
var ErrInvalidChain = errors.New("invalid chain")

// Layer is one layer of a chain: a registered scheme and the options it is built with.
type Layer struct {
	Scheme  string  `json:"scheme"`            // name of a registered layer
	Options Options `json:"options,omitempty"` // values of options the layer accepts
}

// Endpoint is the network and address a chain's innermost layer dials or listens at.
type Endpoint struct {
	Network string `json:"network,omitempty"` // a registered network; empty is resolved from the innermost layer's planes
	Address string `json:"address"`           // written as the network's AddressKind says
}

// Chain lists layers outermost-first over an endpoint, whose empty Network is resolved from the innermost layer's planes as tcp, udp or both.
type Chain struct {
	Layers   []Layer  `json:"layers,omitempty"` // outermost first
	Endpoint Endpoint `json:"endpoint"`         // what the innermost layer reaches
}

// resolved is a looked-up chain whose endpoint expression is expanded below its own layers.
type resolved struct {
	layers []Layer // the chain's own layers, then its endpoint expression's
	own    int     // how many of layers are the chain's own
	specs  []LayerSpec
	planes []Plane // what the chain exposes above each layer, to the next layer out or to its user
	host   string  // the host of the chain's endpoint when it is host:port, which fills the HostKey of its own layers
	inner  string  // the same for the layers of its endpoint expression, of the endpoint that expression dials
	stream string
	packet string
	dial   string    // the address the innermost layer dials: the endpoint's, or its expression's expansion
	listen string    // the address the innermost layer listens at: dial, or the expansion of a Listen expression
	around *Endpoint // where listening goes around the expression's layers, for an expression without Listen
}

func (c Chain) resolve() (*resolved, error) {
	if c.Endpoint.Address == "" && !c.selfClient() {
		return nil, fmt.Errorf("endpoint: empty address: %w", ErrInvalidChain)
	}
	c.Endpoint.Address = c.address()
	r := &resolved{layers: c.Layers, own: len(c.Layers), dial: c.Endpoint.Address, listen: c.Endpoint.Address}
	network := c.Endpoint.Network
	r.host = endpointHost(network, c.Endpoint.Address)
	if ns, _ := lookupNetwork(network); ns.Dial != "" {
		// RegisterNetwork has checked the expressions, so an address filling Dial fills Listen.
		x, _ := parseExpression(ns.Dial)
		dial, err := x.expand(ns.AddressKind, c.Endpoint.Address)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w: %w", network, err, ErrInvalidChain)
		}
		if ns.Listen == "" {
			r.listen, r.around = dial, &c.Endpoint
		} else {
			l, _ := parseExpression(ns.Listen)
			r.listen, _ = l.expand(ns.AddressKind, c.Endpoint.Address)
		}
		inner := x.over(dial)
		r.layers = append(slices.Clip(c.Layers), inner.Layers...)
		network, r.dial = inner.Endpoint.Network, inner.Endpoint.Address
		r.inner = endpointHost(network, r.dial)
	}
	r.specs, r.planes = make([]LayerSpec, len(r.layers)), make([]Plane, len(r.layers))
	for i, l := range r.layers {
		spec, ok := lookupLayer(l.Scheme)
		if !ok {
			return nil, fmt.Errorf("layer %q: unknown scheme: %w", l.Scheme, ErrInvalidChain)
		}
		if spec.isProxy() && i != 0 {
			return nil, fmt.Errorf("layer %q: proxy must be outermost: %w", l.Scheme, ErrInvalidChain)
		}
		for k := range l.Options {
			if !spec.accepts(k) {
				return nil, fmt.Errorf("layer %q: unknown option %q: %w", l.Scheme, k, ErrInvalidChain)
			}
		}
		r.specs[i] = spec
	}
	var avail Plane
	if network == "" {
		if len(r.layers) == 0 {
			return nil, fmt.Errorf("endpoint: network required without layers: %w", ErrInvalidChain)
		}
		inner := r.specs[len(r.specs)-1]
		avail = inner.Requires | inner.Preserves
		if avail&Stream != 0 {
			r.stream = "tcp"
		}
		if avail&Packet != 0 {
			r.packet = "udp"
		}
	} else {
		ns, ok := lookupNetwork(network)
		if !ok {
			return nil, fmt.Errorf("network %q: unknown: %w", network, ErrInvalidChain)
		}
		avail = ns.Plane
		if avail&Stream != 0 {
			r.stream = network
		}
		if avail&Packet != 0 {
			r.packet = network
		}
	}
	if err := r.offer(avail); err != nil {
		return nil, err
	}
	return r, nil
}

// address is the endpoint's address, a host:port one that names no port taking the default of the chain's alias or outermost layer.
func (c Chain) address() string {
	network := c.Endpoint.Network
	if ns, ok := lookupNetwork(network); network != "" && (!ok || ns.AddressKind != AddressHost) {
		return c.Endpoint.Address
	}
	tokens := make([]string, 0, len(c.Layers)+1)
	for _, l := range c.Layers {
		tokens = append(tokens, l.Scheme)
	}
	if network != "" {
		tokens = append(tokens, network)
	}
	return withPort(c.Endpoint.Address, defaultPort(tokens))
}

// endpointHost is the host of address when network, or the tcp or udp an empty one resolves to, writes it as host:port; an IPv6 zone is dropped, as no name or certificate carries one.
func endpointHost(network, address string) string {
	if ns, ok := lookupNetwork(network); network != "" && (!ok || ns.AddressKind != AddressHost) {
		return ""
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	if ip, _, zoned := strings.Cut(host, "%"); zoned && net.ParseIP(ip) != nil {
		return ip
	}
	return host
}

// options are layer i's options for one build, its HostKey filled when the layer leaves it out.
func (r *resolved) options(i int) Options {
	opts := r.layers[i].Options.clone()
	host := r.host
	if i >= r.own {
		host = r.inner
	}
	if key := r.specs[i].HostKey; key != "" && host != "" {
		if _, set := opts[key]; !set {
			opts[key] = host
		}
	}
	return opts
}

// offer applies the chain rule over a carrier of avail; a failing layer offers nothing.
func (r *resolved) offer(avail Plane) error {
	var first error
	// lossy holds the planes of avail that lack datagram boundaries, which no layer is offered.
	var lossy Plane
	for i := len(r.specs) - 1; i >= 0; i-- {
		spec, scheme := r.specs[i], r.layers[i].Scheme
		above := spec.Provides | ((avail &^ lossy) & spec.Preserves)
		var err error
		switch {
		case spec.Requires&lossy != 0:
			err = fmt.Errorf("layer %q requires %v but its carrier keeps no datagram boundaries: %w", scheme, spec.Requires&lossy, ErrInvalidChain)
		case avail&spec.Requires != spec.Requires:
			err = fmt.Errorf("layer %q requires %v but carrier provides %v: %w", scheme, spec.Requires, avail, ErrInvalidChain)
		case above == 0:
			err = fmt.Errorf("layer %q provides no plane: %w", scheme, ErrInvalidChain)
		}
		if err != nil {
			if first == nil {
				first = err
			}
			above = 0
		}
		avail, lossy = above, above&spec.Lossy
		r.planes[i] = avail
		if i > 0 {
			r.planes[i] &^= lossy
		}
	}
	return first
}

// Validate checks, before any I/O, that c names registered layers and networks whose planes fit, wrapping ErrInvalidChain if not.
func (c Chain) Validate() error {
	_, err := c.resolve()
	return err
}

func (c Chain) proxy() (*resolved, error) {
	r, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if len(r.specs) == 0 || !r.specs[0].isProxy() {
		return nil, fmt.Errorf("outermost layer is not a proxy: %w", ErrInvalidChain)
	}
	return r, nil
}
