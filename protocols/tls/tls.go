package tls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func NewTLSDialer(ctx context.Context, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	proxy, ok := permuteproxy.FromContext(ctx)
	if !ok || proxy.Dialer == nil {
		return nil, permuteproxy.ErrNoProxy
	}

	tlsConfig, err := tlsutils.NewClient(metadata)
	if err != nil {
		return nil, err
	}

	return tlsDialer{tlsConfig, proxy.Dialer}, nil
}

func NewTLSListenConfig(ctx context.Context, metadata permuteproxy.Metadata) (permuteproxy.ListenConfig, error) {
	proxy, ok := permuteproxy.FromContext(ctx)
	if !ok || proxy.ListenConfig == nil {
		return nil, permuteproxy.ErrNoProxy
	}

	tlsConfig, err := tlsutils.NewServer(metadata)
	if err != nil {
		return nil, err
	}
	return tlsListenConfig{tlsConfig, proxy.ListenConfig}, nil
}

type tlsDialer struct {
	tlsConfig *tls.Config
	dialer    permuteproxy.Dialer
}

func (n tlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := n.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(c, n.tlsConfig)
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type tlsListenConfig struct {
	tlsConfig    *tls.Config
	listenConfig permuteproxy.ListenConfig
}

func (n tlsListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := n.listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(l, n.tlsConfig), nil
}
