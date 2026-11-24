package permuteproxy

import (
	"errors"
	"fmt"
	"sync"
)

// LayerKind says whether a layer transforms its carrier or speaks a proxy protocol.
type LayerKind uint8

const (
	LayerAdapter LayerKind = iota // turns its carrier into the planes of the layer above, as tls does
	LayerProxy                    // serves or dials a proxy protocol as the outermost layer, as socks5 does
)

// Options are a layer's option values by name.
type Options map[string]string

func (o Options) clone() Options {
	c := make(Options, len(o))
	for k, v := range o {
		c[k] = v
	}
	return c
}

// LayerSpec declares a layer: its kind, the planes it consumes and offers, its options and constructors.
type LayerSpec struct {
	Kind        LayerKind                                 // adapter or proxy
	Requires    Plane                                     // planes the carrier must have, or the chain is invalid; requiring one does not offer it above
	Provides    Plane                                     // planes offered above whatever the carrier has
	Preserves   Plane                                     // carrier planes also offered above, but only those the carrier has
	Lossy       Plane                                     // planes the layer provides without datagram boundaries
	OptionKeys  []string                                  // names of the options the layer accepts
	UsernameKey string                                    // optional; the option a URI's username fills
	PasswordKey string                                    // optional; the option a URI's password fills, beside UsernameKey
	NewAdapter  func(opts Options) (*AdapterFuncs, error) // declares an adapter's links per build
	Networks    []string                                  // base networks the layer's client accepts: tcp, udp, unix, unixgram, ...
	NewClient   func(opts Options) (*ClientFuncs, error)  // declares a proxy's client per build
	NewServer   func(opts Options) (*ServerFuncs, error)  // declares a proxy's server per build
}

func (s LayerSpec) accepts(key string) bool {
	if key == "" {
		return false
	}
	if key == s.UsernameKey || key == s.PasswordKey {
		return true
	}
	for _, o := range s.OptionKeys {
		if o == key {
			return true
		}
	}
	return false
}

// closeOnce calls release, when set, and then closes inner, both at most once.
func closeOnce(release func() error, inner Transport) func() error {
	return sync.OnceValue(func() error {
		var err error
		if release != nil {
			err = release()
		}
		return errors.Join(err, closeIf(inner))
	})
}

// reject calls release, when set, for a declaration the root package refuses, and marks err as an invalid chain unless it is one.
func reject(release func() error, err error) error {
	if release != nil {
		release()
	}
	if errors.Is(err, ErrInvalidChain) {
		return err
	}
	return invalid(err)
}

func invalid(err error) error {
	return fmt.Errorf("%w: %w", err, ErrInvalidChain)
}
