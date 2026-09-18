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

var options = []string{
	"tls_skip_verify",
	"tls_server_name",
	"tls_ca_file",
	"tls_acme_host",
	"tls_acme_cache_dir",
	"tls_cert_file",
	"tls_key_file",
	"tls_self_signed",
}

func Adapt(inner permuteproxy.Transport, opts permuteproxy.Options) (permuteproxy.Transport, error) {
	values := protoutils.Values(opts)
	// Each side's config is built where it is needed: the CA file only by dialers, key material
	// only by listeners.
	clientConfig := sync.OnceValues(func() (*tls.Config, error) { return tlsutils.NewClient(values) })
	return permuteproxy.TransportFuncs{
		Plane: permuteproxy.Stream,
		DialFunc: func(ctx context.Context, _ permuteproxy.Plane) (net.Conn, error) {
			config, err := clientConfig()
			if err != nil {
				return nil, err
			}
			raw, err := inner.Dial(ctx, permuteproxy.Stream)
			if err != nil {
				return nil, err
			}
			// A canceled handshake closes raw itself, so the error path must not close it again.
			raw = &closeOnce{Conn: raw}
			conn := tls.Client(raw, config)
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
		ListenFunc: func(ctx context.Context) (net.Listener, error) {
			serverConfig, err := tlsutils.NewServer(values)
			if err != nil {
				return nil, err
			}
			ln, err := inner.Listen(ctx)
			if err != nil {
				return nil, err
			}
			return tls.NewListener(ln, serverConfig), nil
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
