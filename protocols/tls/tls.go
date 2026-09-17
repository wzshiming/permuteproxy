package tls

import (
	"context"
	"crypto/tls"
	"net"

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
	clientConfig, err := tlsutils.NewClient(values)
	if err != nil {
		return nil, err
	}
	return permuteproxy.TransportFuncs{
		Plane: permuteproxy.Stream,
		DialFunc: func(ctx context.Context, _ permuteproxy.Plane) (net.Conn, error) {
			raw, err := inner.Dial(ctx, permuteproxy.Stream)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, clientConfig)
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
		// Key material is only required from listeners, so the server config is built here.
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
