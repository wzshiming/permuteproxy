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

// AddressKind says how a URI writes a network's address.
type AddressKind uint8

const (
	AddressHost   AddressKind = iota // host:port in the authority, as tcp://127.0.0.1:1080
	AddressPath                      // a path across the authority and path, as unix://./proxy.sock
	AddressOpaque                    // free text after the scheme, as cmd:nc host 1080
)

// ErrInvalidChain is returned, before any I/O, for a chain or declaration the root package cannot build.
var ErrInvalidChain = errors.New("invalid chain")

// Server serves a proxy chain's outermost layer at the chain's endpoint.
type Server interface {
	// Run binds and serves until serving fails, Close is called or ctx ends, returning nil for the last two.
	Run(ctx context.Context) error
	// Close stops Run and releases the server; a Run after Close returns nil at once.
	Close() error
}
