package tls

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func NewAdapter(opts permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	values := protoutils.Values(opts)
	// Each side's config is built where it is needed: the CA file only by dialers, key material
	// only by listeners.
	clientConfig := sync.OnceValues(func() (*tls.Config, error) {
		config, err := tlsutils.NewClient(values)
		if err != nil {
			return nil, err
		}
		// Later dials of the adapter resume the session of an earlier one instead of a full handshake.
		config.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		return config, nil
	})
	return &permuteproxy.AdapterFuncs{
		Stream: &permuteproxy.Link{
			Dial: func(ctx context.Context, carrier func(context.Context) (net.Conn, error)) (net.Conn, error) {
				config, err := clientConfig()
				if err != nil {
					return nil, err
				}
				c, err := carrier(ctx)
				if err != nil {
					return nil, err
				}
				// A canceled handshake closes raw itself, so the error path must not close it again.
				raw := &closeOnce{Conn: c}
				conn := tls.Client(raw, config)
				if err := conn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return conn, nil
			},
			Listen: func(ctx context.Context, carrier func(context.Context) (net.Listener, error)) (net.Listener, error) {
				config, err := tlsutils.NewServer(values)
				if err != nil {
					return nil, err
				}
				ln, err := carrier(ctx)
				if err != nil {
					return nil, err
				}
				return tls.NewListener(ln, config), nil
			},
		},
	}, nil
}

type closeOnce struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *closeOnce) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}
