package sshproxy

import (
	"context"
	"net"
	"net/url"
	"sync"

	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"

	"github.com/wzshiming/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

var options = []string{
	"identity_data",
	"identity_file",
	"authorized_data",
	"authorized_file",
	"hostkey_data",
	"hostkey_file",
}

// endpoint renders the options as the URL form sshproxy parses; the host is a placeholder since
// the inner transport decides where connections go.
func endpoint(opts permuteproxy.Options) string {
	u := url.URL{
		Scheme:   "ssh",
		Host:     "localhost",
		User:     protoutils.Userinfo(opts, KeyUsername, KeyPassword),
		RawQuery: protoutils.Values(opts, KeyUsername, KeyPassword).Encode(),
	}
	return u.String()
}

func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	dialer, err := sshproxy.NewDialer(endpoint(opts))
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return &permuteproxy.ClientFuncs{
		Dial: func(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
			once.Do(func() {
				dialer.ProxyDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					return inner.Dial(ctx, permuteproxy.Stream)
				}
			})
			return dialer.DialContext(ctx, network, address)
		},
		Close: dialer.Close,
	}, nil
}

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	simple, err := sshproxy.NewSimpleServer(endpoint(opts))
	if err != nil {
		return nil, err
	}
	return &permuteproxy.ServerFuncs{
		Serve: func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
			srv := simple.Server
			srv.Context = ctx
			srv.ProxyDial = upstream.DialContext
			srv.ProxyListen = upstream.Listen
			srv.BytesPool = pool.Bytes
			return srv.Serve(ln)
		},
	}, nil
}
