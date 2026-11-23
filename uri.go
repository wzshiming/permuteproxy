package permuteproxy

import (
	"fmt"
	"net/url"
	"strings"
)

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
		if r.own == 0 || r.specs[0].UsernameKey == "" {
			return Chain{}, fmt.Errorf("uri: %q does not accept credentials: %w", u.Scheme, ErrInvalidChain)
		}
		c.Layers[0].set(r.specs[0].UsernameKey, u.User.Username())
		if password, ok := u.User.Password(); ok {
			if r.specs[0].PasswordKey == "" {
				return Chain{}, fmt.Errorf("uri: %q does not accept a password: %w", u.Scheme, ErrInvalidChain)
			}
			c.Layers[0].set(r.specs[0].PasswordKey, password)
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
		if username, ok := opts[spec.UsernameKey]; ok {
			query.Del(spec.UsernameKey)
			u.User = url.User(username)
			if password, ok := opts[spec.PasswordKey]; ok {
				query.Del(spec.PasswordKey)
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
