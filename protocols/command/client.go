package command

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/cmdutils"
)

// NewClient builds the client a bare command line is, as cmd:ssh -W %h:%p jump: each dial of a
// tcp or unix address runs the filled line on base's cmd network, and each listener runs it once
// per connection, as nc -l %h %p accepts one.
func NewClient(base permuteproxy.Network, line string) (permuteproxy.Network, error) {
	t := cmdutils.Template(line)
	if err := t.Check(); err != nil {
		return nil, err
	}
	fill := func(op, network, address string) (string, error) {
		command, err := t.Fill(network, address)
		if errors.Is(err, errors.ErrUnsupported) {
			err = permuteproxy.ErrUnsupported
		}
		if err != nil {
			return "", fmt.Errorf("%s %s %s: %w", op, network, address, err)
		}
		return command, nil
	}
	return permuteproxy.NetworkFuncs{
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			command, err := fill("dial", network, address)
			if err != nil {
				return nil, err
			}
			return base.DialContext(ctx, "cmd", command)
		},
		ListenFunc: func(ctx context.Context, network, address string) (net.Listener, error) {
			command, err := fill("listen", network, address)
			if err != nil {
				return nil, err
			}
			return base.Listen(ctx, "cmd", command)
		},
	}, nil
}
