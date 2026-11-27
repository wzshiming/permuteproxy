// Package netcat reaches and accepts connections by running netcat, over the network cmd that
// protocols/cmd registers. It registers the endpoint networks cmd-nc, cmd-nc-unix and
// cmd-nc-udp and cmd-nc-unixgram, each an address one nc per connection dials, listens at or
// binds, and nc, or netcat, the client that runs an nc per target: over tcp, udp or a unix
// socket, stream or datagram.
package netcat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
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
	// DialUnixgram has nc bind a socket file of its own under /tmp, where the peer's answers arrive.
	DialUnixgram = "nc -U -u -w 30 %h"
	// ListenUnixgram serves one peer as ListenUDP does, and leaves its socket file behind.
	ListenUnixgram = "nc -U -u -l %h"
)

// networks are the networks a client reaches, each with the template of its base and the flag of its family.
var networks = map[string]struct{ dial, listen, family string }{
	"tcp":      {DialTCP, ListenTCP, ""},
	"tcp4":     {DialTCP, ListenTCP, "-4"},
	"tcp6":     {DialTCP, ListenTCP, "-6"},
	"unix":     {DialUnix, ListenUnix, ""},
	"udp":      {DialUDP, ListenUDP, ""},
	"udp4":     {DialUDP, ListenUDP, "-4"},
	"udp6":     {DialUDP, ListenUDP, "-6"},
	"unixgram": {DialUnixgram, ListenUnixgram, ""},
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

// NewClient builds the client of nc:[prefix] over the network over, whose network cmd runs the command lines.
// A dial of a tcp address runs nc %h %p, of a unix address nc -U %h, of a udp address
// nc -u -w 30 %h %p and of a unixgram address nc -U -u -w 30 %h, the last two carrying
// best-effort datagrams; tcp4, udp4, tcp6 and udp6 add -4 or -6. A listener runs nc -l, or
// nc -Ul, once per connection. A udp socket bound at an unspecified host with port 0 reaches each
// peer through an nc of its own; a datagram socket bound at any other address is one nc -u -l
// %h %p, or nc -U -u -l %h, which serves a single peer. prefix is what each line is run
// behind, as ssh jump runs netcat on jump.
func NewClient(over permuteproxy.Network, prefix string) (permuteproxy.Network, error) {
	// The prefix is literal text, so a '%' in it is not a placeholder.
	prefix = strings.ReplaceAll(strings.TrimSpace(prefix), "%", "%%")
	c := &client{base: over, bare: prefix == "", dial: map[string]cmdutils.Template{}, listen: map[string]cmdutils.Template{}}
	for network, n := range networks {
		c.dial[network] = cmdutils.Template(line(prefix, n.dial, n.family))
		c.listen[network] = cmdutils.Template(line(prefix, n.listen, n.family))
		if err := errors.Join(c.dial[network].Check(), c.listen[network].Check()); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// client runs an nc per target; dial and listen hold, per network, the line it runs on the cmd network of base.
type client struct {
	base         permuteproxy.Network
	bare         bool // no prefix, so nc runs where base runs commands
	dial, listen map[string]cmdutils.Template
}

// run fills t for address on network, a tcp or unix one, and runs the line on the cmd network of base.
func run(ctx context.Context, base permuteproxy.Network, t cmdutils.Template, network, address string) (net.Conn, error) {
	command, err := t.Fill(network, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
	}
	return base.DialContext(ctx, "cmd", command)
}

func datagram(network string) bool {
	return strings.HasPrefix(network, "udp") || network == "unixgram"
}

// stream is the network a template fills network's address for: it knows a host and
// port for tcp and a path for unix alone, and the line itself is what makes nc send datagrams.
func stream(network string) string {
	if network == "unixgram" || network == "cmd-nc-unixgram" {
		return "unix"
	}
	return "tcp"
}

// base is the network a datagram socket of network reports its addresses on.
func base(network string) string {
	if stream(network) == "unix" {
		return "unixgram"
	}
	return "udp"
}

func (c *client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	filled, ok := c.dial[network]
	if !ok {
		return nil, fmt.Errorf("dial %s: %w", network, permuteproxy.ErrUnsupported)
	}
	if !datagram(network) {
		return run(ctx, c.base, filled, network, address)
	}
	conn, err := run(ctx, c.base, filled, stream(network), address)
	if err != nil {
		return nil, err
	}
	return netutils.StreamPacket(conn, netutils.NewNetAddr(base(network), address)), nil
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
	command, err := filled.Fill(network, address)
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", network, address, err)
	}
	return c.base.Listen(ctx, "cmd", command)
}

// ListenPacket on udp at an unspecified host with port 0 binds no address of its own: each peer
// is reached by an nc dialing it. At any other address, and on unixgram, it is one nc -u -l,
// serving a single peer.
func (c *client) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	filled, ok := c.listen[network]
	if !ok || !datagram(network) {
		return nil, fmt.Errorf("listen packet %s: %w", network, permuteproxy.ErrUnsupported)
	}
	if host, port, err := net.SplitHostPort(address); network == "unixgram" || err != nil || port != "0" || host != "" && !net.ParseIP(host).IsUnspecified() {
		return listenPacket(ctx, c.base, filled, network, address)
	}
	return netutils.NewSessions(func(ctx context.Context, peer net.Addr) (net.Conn, error) {
		return c.DialContext(ctx, network, peer.String())
	}, netutils.SessionOptions{}), nil
}

// listenPacket runs filled, an nc -u -l line, on the cmd of over as a datagram socket of
// network at address. nc serves a single peer: it answers whoever sends the first datagram and takes
// datagrams from nobody else for as long as it runs, so the socket is good for one peer until
// it is closed. nc does not tell who that peer is, so ReadFrom reports the command itself as
// the peer and WriteTo reaches the peer only through that address; what is written before
// the peer's first datagram waits in nc's stdin until it arrives. Datagrams cross nc's stdio
// as a stream, so their boundaries are best-effort.
func listenPacket(ctx context.Context, over permuteproxy.Network, filled cmdutils.Template, network, address string) (net.PacketConn, error) {
	conn, err := run(ctx, over, filled, stream(network), address)
	if err != nil {
		return nil, err
	}
	peer := conn.RemoteAddr()
	return netutils.StreamPacket(netutils.ConnWithAddr(conn, netutils.NewNetAddr(base(network), address), nil), peer).(net.PacketConn), nil
}

// Lossy reports udp and unixgram, whose datagrams cross nc's stdio as a stream.
func (c *client) Lossy(network string) bool {
	return datagram(network)
}
