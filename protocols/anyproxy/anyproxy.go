package anyproxy

import (
	"context"
	"net"
	"net/url"

	"github.com/wzshiming/anyproxy"
	_ "github.com/wzshiming/anyproxy/proxies/httpproxy"
	_ "github.com/wzshiming/anyproxy/proxies/socks4"
	_ "github.com/wzshiming/anyproxy/proxies/socks5"
	_ "github.com/wzshiming/anyproxy/proxies/sshproxy"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "username"
	KeyPassword = "password"
)

var protocols = []string{"http", "socks4", "socks5", "ssh"}

// host keys every handler under one placeholder; the inner transport owns the real endpoint.
const host = "localhost"

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	user := protoutils.Userinfo(opts, KeyUsername, KeyPassword)
	addrs := make([]string, 0, len(protocols))
	for _, scheme := range protocols {
		u := url.URL{Scheme: scheme, Host: host, User: user}
		addrs = append(addrs, u.String())
	}
	conf := &anyproxy.Config{
		Dialer:       upstream,
		ListenConfig: upstream,
		BytesPool:    pool.Bytes,
	}
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		proxy, err := anyproxy.NewAnyProxy(ctx, addrs, conf)
		if err != nil {
			return err
		}
		return proxy.Match(host).Serve(ln)
	}), nil
}
