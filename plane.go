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

type AddressKind uint8

const (
	AddressHost AddressKind = iota
	AddressPath
	AddressOpaque
)

var ErrInvalidChain = errors.New("invalid chain")

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
	Kind           Kind
	Requires       Plane // planes the carrier must have, or the chain is invalid; requiring one does not offer it above
	Provides       Plane // planes offered above whatever the carrier has
	Preserves      Plane // carrier planes also offered above, but only those the carrier has
	Options        []string
	UsernameOption string
	PasswordOption string
	Adapt          func(inner Transport, opts Options) (Transport, error)
	NewAdapter     func(opts Options) (*AdapterFuncs, error) // declares an adapter's links per build, as the alternative to Adapt
	Client         func(inner Transport, base Network, opts Options) (Network, error)
	Networks       []string                                 // base networks the layer's client accepts: tcp, udp, unix, unixgram, ...
	NewClient      func(opts Options) (*ClientFuncs, error) // declares a proxy's client per build, as the alternative to Client
	Server         func(inner Transport, upstream Network, opts Options) (Server, error)
	NewServer      func(opts Options) (*ServerFuncs, error) // declares a proxy's server per build, as the alternative to Server
}

// Server serves a proxy chain's outermost layer at the chain's endpoint.
type Server interface {
	// Run binds and serves until serving fails, Close is called or ctx ends, returning nil for the last two.
	Run(ctx context.Context) error
	// Close stops Run and releases the server; a Run after Close returns nil at once.
	Close() error
}
