package permuteproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/wzshiming/permuteproxy/internal/cmdutils"
)

// templated reports whether c is a bare command line, such as cmd:ssh -W %h:%p jump, which a ClientEngine fills per dial.
func (c Chain) templated() bool {
	return len(c.Layers) == 0 && c.Endpoint.Network == "cmd"
}

// commandTemplate is a command line a client fills per dial or listen: %h is the host, or the
// socket path for unix, %p the port, empty for unix, %n the network and "%%" a '%'.
type commandTemplate string

// check refuses a '%' that starts no placeholder.
func (t commandTemplate) check() error {
	for i := 0; i < len(t); i++ {
		if t[i] != '%' {
			continue
		}
		p := string(t[i:min(i+2, len(t))])
		if len(p) < 2 || strings.IndexByte("hpn%", p[1]) < 0 {
			return fmt.Errorf("placeholder %q is unknown", p)
		}
		i++
	}
	return nil
}

// fill writes the command line for address on network. The values enter verbatim, wherever the
// template puts them, quotes and sh -c included, so only those every shell reads as plain text
// are taken: however often the line is parsed again, as by ssh, a value stays within its word.
func (t commandTemplate) fill(network, address string) (string, error) {
	var host, port string
	switch base, _, _ := lookupBase(network); base {
	case "tcp":
		var err error
		if host, port, err = splitTarget(address); err != nil {
			return "", err
		}
	case "unix":
		if address == "" || address[0] == '-' || !utf8.ValidString(address) || !cmdutils.Plain(address) {
			return "", errors.New("path is empty, starts with '-' or has a byte other than ASCII letters, digits and \"%+,-./:@_\"")
		}
		host = address
	default:
		return "", ErrUnsupported
	}
	return strings.NewReplacer("%h", host, "%p", port, "%n", network, "%%", "%").Replace(string(t)), nil
}

// template builds the client of a templated chain: each dial of a tcp or unix address runs the
// filled command over Base, and each listener runs it per connection, as nc -l %h %p accepts one.
func (e ClientEngine) template(c Chain) (Network, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	t := commandTemplate(c.Endpoint.Address)
	if err := t.check(); err != nil {
		return nil, fmt.Errorf("endpoint: %w: %w", err, ErrInvalidChain)
	}
	base := orByName(e.Base)
	return NetworkFuncs{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			command, err := t.fill(network, address)
			if err != nil {
				return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
			}
			return base.DialContext(ctx, "cmd", command)
		},
		ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
			command, err := t.fill(network, address)
			if err != nil {
				return nil, fmt.Errorf("listen %s %s: %w", network, address, err)
			}
			return base.Listen(ctx, "cmd", command)
		},
	}, nil
}
