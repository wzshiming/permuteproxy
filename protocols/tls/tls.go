package tls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/tlsutils"
)

func NewTLSDialer(dialer permuteproxy.Dialer, metadata permuteproxy.Metadata) (permuteproxy.Dialer, error) {
	tlsConfig, err := tlsutils.NewClient(metadata)
	if err != nil {
		return nil, err
	}
	return tlsDialer{tlsConfig, dialer}, nil
}

func NewTLSListenConfig(listenConfig permuteproxy.ListenConfig, metadata permuteproxy.Metadata) (permuteproxy.ListenConfig, error) {
	tlsConfig, err := tlsutils.NewServer(metadata)
	if err != nil {
		return nil, err
	}
	return tlsListenConfig{tlsConfig, listenConfig}, nil
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
