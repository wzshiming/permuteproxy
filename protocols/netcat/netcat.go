// Package netcat reaches and accepts connections by running netcat, over the network cmd that
// protocols/local registers. It registers the endpoint networks cmd-nc, cmd-nc-unix and
// cmd-nc-udp, each an address one nc per connection dials, or for the first two listens at,
// and nc, or netcat, the client that runs an nc per target: over tcp, udp or a unix socket.
package netcat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/netutils"
)

// Command templates: %h is the host, or the socket path for unix, and %p the port.
const (
	DialTCP    = "nc %h %p"
	ListenTCP  = "nc -l %h %p"
	DialUnix   = "nc -U %h"
	ListenUnix = "nc -Ul %h"
	DialUDP    = "nc -u -w 30 %h %p"
	// ListenUDP serves one peer: nc answers whoever sends the first datagram, and nobody else after.
	ListenUDP = "nc -u -l %h %p"
)

// networks are the networks a client reaches, each with the template of its base and the flag of its family.
var networks = map[string]struct{ dial, listen, family string }{
	"tcp":  {DialTCP, ListenTCP, ""},
	"tcp4": {DialTCP, ListenTCP, "-4"},
	"tcp6": {DialTCP, ListenTCP, "-6"},
	"unix": {DialUnix, ListenUnix, ""},
	"udp":  {DialUDP, ListenUDP, ""},
	"udp4": {DialUDP, ListenUDP, "-4"},
	"udp6": {DialUDP, ListenUDP, "-6"},
}

// line is template run behind prefix, with the flag of its family.
func line(prefix, template, family string) string {
	if family != "" {
		template = strings.Replace(template, "nc ", "nc "+family+" ", 1)
	}
	if prefix != "" {
		template = prefix + " " + template
	}
	return template
}

// NewClient builds the client of nc:[prefix] over base, whose network cmd runs the command lines.
// A dial of a tcp address runs nc %h %p, of a unix address nc -U %h and of a udp address
// nc -u -w 30 %h %p, whose conn carries best-effort datagrams; tcp4, udp4, tcp6 and udp6 add -4 or
// -6. A listener runs nc -l, or nc -Ul, once per connection. A datagram socket bound at an
// unspecified host with port 0 reaches each peer through an nc of its own; bound at any other
// address it is one nc -u -l %h %p, which serves a single peer. prefix is what each line is run
// behind, as ssh jump runs netcat on jump.
func NewClient(base permuteproxy.Network, prefix string) (permuteproxy.Network, error) {
	// The prefix is literal text, so a '%' in it is not a placeholder.
	prefix = strings.ReplaceAll(strings.TrimSpace(prefix), "%", "%%")
	c := &client{base: base, bare: prefix == "", dial: map[string]permuteproxy.Network{}, listen: map[string]permuteproxy.Network{}}
	engine := permuteproxy.ClientEngine{Base: base}
	for network, n := range networks {
		for template, clients := range map[string]map[string]permuteproxy.Network{n.dial: c.dial, n.listen: c.listen} {
			filled, err := engine.Client(permuteproxy.Chain{Endpoint: permuteproxy.Endpoint{Network: "cmd", Address: line(prefix, template, n.family)}})
			if err != nil {
				return nil, err
			}
			clients[network] = filled
		}
	}
	return c, nil
}

// client runs an nc per target; dial and listen hold, per network, the command client of its line.
type client struct {
	base         permuteproxy.Network
	bare         bool // no prefix, so nc runs where base runs commands
	dial, listen map[string]permuteproxy.Network
}

func datagram(network string) bool {
	return strings.HasPrefix(network, "udp")
}

func (c *client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	filled, ok := c.dial[network]
	if !ok {
		return nil, fmt.Errorf("dial %s: %w", network, permuteproxy.ErrUnsupported)
	}
	if !datagram(network) {
		return filled.DialContext(ctx, network, address)
	}
	// A command client fills a host and port for tcp alone; the line itself is what makes it udp.
	conn, err := filled.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return netutils.StreamPacket(conn, netutils.NewNetAddr("udp", address)), nil
}

func (c *client) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	filled, ok := c.listen[network]
	if !ok || datagram(network) {
		return nil, fmt.Errorf("listen %s: %w", network, permuteproxy.ErrUnsupported)
	}
	if network == "unix" && c.bare {
		// A base that listens on cmd-nc-unix, as Network does, removes the socket file nc leaves behind.
		ln, err := c.base.Listen(ctx, "cmd-nc-unix", address)
		if !errors.Is(err, permuteproxy.ErrUnsupported) {
			return ln, err
		}
	}
	return filled.Listen(ctx, network, address)
}

// ListenPacket at an unspecified host with port 0 binds no address of its own: each peer is
// reached by an nc dialing it. At any other address it is one nc -u -l, serving a single peer.
func (c *client) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	filled, ok := c.listen[network]
	if !ok || !datagram(network) {
		return nil, fmt.Errorf("listen packet %s: %w", network, permuteproxy.ErrUnsupported)
	}
	if host, port, err := net.SplitHostPort(address); err != nil || port != "0" || host != "" && !net.ParseIP(host).IsUnspecified() {
		return listenPacket(ctx, filled, address)
	}
	return netutils.NewSessions(func(ctx context.Context, peer net.Addr) (net.Conn, error) {
		return c.DialContext(ctx, network, peer.String())
	}, netutils.SessionOptions{}), nil
}

// listenPacket runs the nc -u -l line of filled, a command client, as a datagram socket at
// address. nc serves a single peer: it answers whoever sends the first datagram and takes
// datagrams from nobody else for as long as it runs, so the socket is good for one peer until
// it is closed. nc does not tell who that peer is, so ReadFrom reports the command itself as
// the peer and WriteTo reaches the peer only through that address; what is written before
// the peer's first datagram waits in nc's stdin until it arrives. Datagrams cross nc's stdio
// as a stream, so their boundaries are best-effort.
func listenPacket(ctx context.Context, filled permuteproxy.Network, address string) (net.PacketConn, error) {
	// A command client fills a host and port for tcp alone; the line itself is what makes it udp.
	conn, err := filled.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	peer := conn.RemoteAddr()
	return netutils.StreamPacket(netutils.ConnWithAddr(conn, netutils.NewNetAddr("udp", address), nil), peer).(net.PacketConn), nil
}

// Lossy reports udp, whose datagrams cross nc's stdio as a stream.
func (c *client) Lossy(network string) bool {
	return datagram(network)
}
