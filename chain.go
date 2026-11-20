package permuteproxy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

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

// Chain lists layers outermost-first over an endpoint; an empty Endpoint.Network is resolved
// from the innermost layer's planes (tcp, udp, or both).
type Chain struct {
	Layers   []Layer  `json:"layers,omitempty"` // outermost first
	Endpoint Endpoint `json:"endpoint"`         // what the innermost layer reaches
}

// resolved is a looked-up chain whose endpoint expression is expanded below its own layers.
type resolved struct {
	layers []Layer // the chain's own layers, then its endpoint expression's
	own    int     // how many of layers are the chain's own
	specs  []Spec
	planes []Plane // what the chain exposes above each layer, to the next layer out or to its user
	stream string
	packet string
	dial   string    // the address the innermost layer dials: the endpoint's, or its expression's expansion
	listen string    // the address the innermost layer listens at: dial, or the expansion of a Listen expression
	around *Endpoint // where listening goes around the expression's layers, for an expression without Listen
}

func (s Spec) accepts(key string) bool {
	if key == "" {
		return false
	}
	if key == s.UsernameOption || key == s.PasswordOption {
		return true
	}
	for _, o := range s.Options {
		if o == key {
			return true
		}
	}
	return false
}

func (c Chain) resolve() (*resolved, error) {
	if c.Endpoint.Address == "" {
		return nil, fmt.Errorf("endpoint: empty address: %w", ErrInvalidChain)
	}
	r := &resolved{layers: c.Layers, own: len(c.Layers), dial: c.Endpoint.Address, listen: c.Endpoint.Address}
	network := c.Endpoint.Network
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
	}
	r.specs, r.planes = make([]Spec, len(r.layers)), make([]Plane, len(r.layers))
	for i, l := range r.layers {
		spec, ok := lookupLayer(l.Scheme)
		if !ok {
			return nil, fmt.Errorf("layer %q: unknown scheme: %w", l.Scheme, ErrInvalidChain)
		}
		if spec.Kind == KindProxy && i != 0 {
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

func addressKind(network string) AddressKind {
	if ns, ok := lookupNetwork(network); ok {
		return ns.AddressKind
	}
	return AddressHost
}

// address is the endpoint text a parsed URI carries for the given kind.
func address(u *url.URL, kind AddressKind) string {
	switch kind {
	case AddressPath:
		return u.Host + u.Path
	case AddressOpaque:
		return u.Opaque
	}
	return u.Host
}

// ParseURI reads a chain whose scheme joins its layers and network with '+', its address read as the network's AddressKind writes it.
func ParseURI(raw string) (Chain, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Chain{}, fmt.Errorf("uri: malformed: %w", ErrInvalidChain)
	}
	if u.Scheme == "" {
		return Chain{}, fmt.Errorf("uri: missing scheme: %w", ErrInvalidChain)
	}
	tokens := expandAliases(strings.Split(u.Scheme, "+"))
	c := Chain{}
	if _, ok := lookupNetwork(tokens[len(tokens)-1]); ok {
		c.Endpoint.Network = tokens[len(tokens)-1]
		tokens = tokens[:len(tokens)-1]
	}
	c.Endpoint.Address = address(u, addressKind(c.Endpoint.Network))
	for _, t := range tokens {
		c.Layers = append(c.Layers, Layer{Scheme: t})
	}
	r, err := c.resolve()
	if err != nil {
		return Chain{}, err
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Chain{}, fmt.Errorf("uri: malformed query: %w", ErrInvalidChain)
	}
	for k, vs := range query {
		i := r.owner(k)
		if i < 0 {
			return Chain{}, fmt.Errorf("uri: unknown option %q: %w", k, ErrInvalidChain)
		}
		c.Layers[i].set(k, vs[len(vs)-1])
	}
	if u.User != nil {
		if r.own == 0 || r.specs[0].UsernameOption == "" {
			return Chain{}, fmt.Errorf("uri: %q does not accept credentials: %w", u.Scheme, ErrInvalidChain)
		}
		c.Layers[0].set(r.specs[0].UsernameOption, u.User.Username())
		if password, ok := u.User.Password(); ok {
			if r.specs[0].PasswordOption == "" {
				return Chain{}, fmt.Errorf("uri: %q does not accept a password: %w", u.Scheme, ErrInvalidChain)
			}
			c.Layers[0].set(r.specs[0].PasswordOption, password)
		}
	}
	return c, nil
}

// owner returns the outermost of the chain's own layers accepting key, which is where ParseURI assigns it.
func (r *resolved) owner(key string) int {
	for i, spec := range r.specs[:r.own] {
		if spec.accepts(key) {
			return i
		}
	}
	return -1
}

func (l *Layer) set(key, value string) {
	if l.Options == nil {
		l.Options = Options{}
	}
	l.Options[key] = value
}

// URI writes c as the URI ParseURI reads back, refusing an address no URI carries unchanged.
func (c Chain) URI() (string, error) {
	r, err := c.resolve()
	if err != nil {
		return "", err
	}
	u := &url.URL{}
	query := url.Values{}
	tokens := make([]string, 0, len(c.Layers)+1)
	for i, l := range c.Layers {
		tokens = append(tokens, l.Scheme)
		for k, v := range l.Options {
			if r.owner(k) != i {
				return "", fmt.Errorf("layer %q: option %q would be parsed into layer %q: %w", l.Scheme, k, c.Layers[r.owner(k)].Scheme, ErrInvalidChain)
			}
			query.Set(k, v)
		}
	}
	kind := addressKind(c.Endpoint.Network)
	// url.URL drops userinfo when Opaque is set, so opaque endpoints keep credentials in the query.
	if len(c.Layers) > 0 && kind != AddressOpaque {
		spec, opts := r.specs[0], c.Layers[0].Options
		if username, ok := opts[spec.UsernameOption]; ok {
			query.Del(spec.UsernameOption)
			u.User = url.User(username)
			if password, ok := opts[spec.PasswordOption]; ok {
				query.Del(spec.PasswordOption)
				u.User = url.UserPassword(username, password)
			}
		}
	}
	if c.Endpoint.Network != "" {
		tokens = append(tokens, c.Endpoint.Network)
	}
	u.Scheme = strings.Join(foldAliases(tokens), "+")
	switch kind {
	case AddressHost:
		u.Host = c.Endpoint.Address
	case AddressPath:
		u.Path = c.Endpoint.Address
	case AddressOpaque:
		u.Opaque = c.Endpoint.Address
	}
	u.RawQuery = query.Encode()
	// url.URL escapes or splits some addresses into other components, so only text that reads back is emitted.
	s := u.String()
	p, err := url.Parse(s)
	if err != nil || p.User.String() != u.User.String() || address(p, kind) != c.Endpoint.Address {
		return "", fmt.Errorf("endpoint: address not representable as URI: %w", ErrInvalidChain)
	}
	return s, nil
}
