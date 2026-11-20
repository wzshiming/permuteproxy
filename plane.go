package permuteproxy

import (
	"context"
	"errors"
	"strings"
)

// Plane is a set of the kinds of carrier a transport offers: byte streams, datagrams or both.
type Plane uint8

const (
	Stream Plane = 1 << iota // reliable ordered byte streams, as tcp carries
	Packet                   // datagrams each with its peer, as udp carries
)

// String names the planes in p joined by '|', or "none".
func (p Plane) String() string {
	var names []string
	if p&Stream != 0 {
		names = append(names, "stream")
	}
	if p&Packet != 0 {
		names = append(names, "packet")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}

// Kind says whether a layer transforms its carrier or speaks a proxy protocol.
type Kind uint8

const (
	KindAdapter Kind = iota // turns its carrier into the planes of the layer above, as tls does
	KindProxy               // serves or dials a proxy protocol as the outermost layer, as socks5 does
)

// AddressKind says how a URI writes a network's address.
type AddressKind uint8

const (
	AddressHost   AddressKind = iota // host:port in the authority, as tcp://127.0.0.1:1080
	AddressPath                      // a path across the authority and path, as unix://./proxy.sock
	AddressOpaque                    // free text after the scheme, as cmd:nc host 1080
)

// ErrInvalidChain is returned, before any I/O, for a chain or declaration the root package cannot build.
var ErrInvalidChain = errors.New("invalid chain")

// Options are a layer's option values by name.
type Options map[string]string

func (o Options) clone() Options {
	c := make(Options, len(o))
	for k, v := range o {
		c[k] = v
	}
	return c
}

// Spec declares a layer: its kind, the planes it consumes and offers, its options and constructors.
type Spec struct {
	Kind           Kind                                      // adapter or proxy
	Requires       Plane                                     // planes the carrier must have, or the chain is invalid; requiring one does not offer it above
	Provides       Plane                                     // planes offered above whatever the carrier has
	Preserves      Plane                                     // carrier planes also offered above, but only those the carrier has
	Lossy          Plane                                     // planes the layer provides without datagram boundaries
	Options        []string                                  // names of the options the layer accepts
	UsernameOption string                                    // optional; the option a URI's username fills
	PasswordOption string                                    // optional; the option a URI's password fills, beside UsernameOption
	NewAdapter     func(opts Options) (*AdapterFuncs, error) // declares an adapter's links per build
	Networks       []string                                  // base networks the layer's client accepts: tcp, udp, unix, unixgram, ...
	NewClient      func(opts Options) (*ClientFuncs, error)  // declares a proxy's client per build
	NewServer      func(opts Options) (*ServerFuncs, error)  // declares a proxy's server per build
}

// Server serves a proxy chain's outermost layer at the chain's endpoint.
type Server interface {
	// Run binds and serves until serving fails, Close is called or ctx ends, returning nil for the last two.
	Run(ctx context.Context) error
	// Close stops Run and releases the server; a Run after Close returns nil at once.
	Close() error
}
