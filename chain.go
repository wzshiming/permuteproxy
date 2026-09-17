package permuteproxy

import (
	"fmt"
	"net/url"
	"strings"
)

type Layer struct {
	Scheme  string  `json:"scheme"`
	Options Options `json:"options,omitempty"`
}

type Endpoint struct {
	Network string `json:"network,omitempty"`
	Address string `json:"address"`
}

// Chain lists layers outermost-first over an endpoint; an empty Endpoint.Network is resolved
// from the innermost layer's planes (tcp, udp, or both).
type Chain struct {
	Layers   []Layer  `json:"layers,omitempty"`
	Endpoint Endpoint `json:"endpoint"`
}

// resolved holds the looked-up specs; planes[i] is what the chain exposes above layer i.
type resolved struct {
	specs  []Spec
	planes []Plane
	impl   Network
	stream string
	packet string
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
	r := &resolved{specs: make([]Spec, len(c.Layers)), planes: make([]Plane, len(c.Layers))}
	for i, l := range c.Layers {
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
	if c.Endpoint.Network == "" {
		if len(c.Layers) == 0 {
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
		ns, ok := lookupNetwork(c.Endpoint.Network)
		if !ok {
			return nil, fmt.Errorf("network %q: unknown: %w", c.Endpoint.Network, ErrInvalidChain)
		}
		avail = ns.Plane
		if avail&Stream != 0 {
			r.stream = c.Endpoint.Network
		}
		if avail&Packet != 0 {
			r.packet = c.Endpoint.Network
		}
		r.impl = ns.Network
	}
	for i := len(r.specs) - 1; i >= 0; i-- {
		spec := r.specs[i]
		if avail&spec.Requires != spec.Requires {
			return nil, fmt.Errorf("layer %q requires %v but carrier provides %v: %w", c.Layers[i].Scheme, spec.Requires, avail, ErrInvalidChain)
		}
		avail = spec.Provides | (avail & spec.Preserves)
		if avail == 0 {
			return nil, fmt.Errorf("layer %q provides no plane: %w", c.Layers[i].Scheme, ErrInvalidChain)
		}
		r.planes[i] = avail
	}
	return r, nil
}

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
	switch addressKind(c.Endpoint.Network) {
	case AddressHost:
		c.Endpoint.Address = u.Host
	case AddressPath:
		c.Endpoint.Address = u.Host + u.Path
	case AddressOpaque:
		c.Endpoint.Address = u.Opaque
	}
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
		if len(r.specs) == 0 || r.specs[0].UsernameOption == "" {
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

// owner returns the outermost layer accepting key, which is where ParseURI assigns it.
func (r *resolved) owner(key string) int {
	for i, spec := range r.specs {
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
		// Opaque text is emitted verbatim, so anything url.Parse would split off cannot round-trip.
		if strings.ContainsAny(c.Endpoint.Address, "?#") || strings.HasPrefix(c.Endpoint.Address, "/") {
			return "", fmt.Errorf("endpoint: opaque address not representable as URI: %w", ErrInvalidChain)
		}
		u.Opaque = c.Endpoint.Address
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}
