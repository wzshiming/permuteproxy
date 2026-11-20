package tls

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func NewAdapter(opts permuteproxy.Options) (*permuteproxy.AdapterFuncs, error) {
	values := protoutils.Values(opts)
	// Each side's config is built where it is needed: the CA file only by dialers, key material
	// only by listeners.
	clientConfig := sync.OnceValues(func() (*tls.Config, error) { return tlsutils.NewClient(values) })
	var serverConfig atomic.Pointer[tls.Config] // what the latest BeforeListen built
	return &permuteproxy.AdapterFuncs{
		BeforeDial: func() error {
			_, err := clientConfig()
			return err
		},
		BeforeListen: func() error {
			config, err := tlsutils.NewServer(values)
			if err != nil {
				return err
			}
			serverConfig.Store(config)
			return nil
		},
		Stream: &permuteproxy.Link{
			Client: func(ctx context.Context, carrier net.Conn) (net.Conn, error) {
				config, _ := clientConfig() // BeforeDial has returned its error
				// A canceled handshake closes raw itself, so the error path must not close it again.
				raw := &closeOnce{Conn: carrier}
				conn := tls.Client(raw, config)
				if err := conn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return conn, nil
			},
			Listener: func(ln net.Listener) (net.Listener, error) {
				return tls.NewListener(ln, serverConfig.Load()), nil
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
