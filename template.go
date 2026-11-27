package permuteproxy

import (
	"context"
	"fmt"
	"net"
)

// templated reports whether c is a bare command line, such as cmd:ssh -W %h:%p jump, which a ClientEngine fills per dial.
func (c Chain) templated() bool {
	return len(c.Layers) == 0 && c.Endpoint.Network == "cmd"
}

// template builds the client of a templated chain: each tcp dial runs the command over Base with the target's host for %h and port for %p, filled as an expression's are.
func (e ClientEngine) template(c Chain) (Network, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	x := expression{network: "cmd", opaque: true, template: c.Endpoint.Address}
	if err := x.check(AddressHost); err != nil {
		return nil, fmt.Errorf("endpoint: %w: %w", err, ErrInvalidChain)
	}
	base := orByName(e.Base)
	return NetworkFuncs{DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		if name, _, _ := lookupBase(network); name != "tcp" {
			return nil, fmt.Errorf("dial %s: %w", network, ErrUnsupported)
		}
		command, err := x.expand(AddressHost, address)
		if err != nil {
			return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
		}
		return base.DialContext(ctx, "cmd", command)
	}}, nil
}
