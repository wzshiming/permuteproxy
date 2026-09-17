package shadowsocks

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/wzshiming/shadowsocks"
	_ "github.com/wzshiming/shadowsocks/init"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
	"github.com/wzshiming/permuteproxy/internal/protoutils"
)

const (
	KeyUsername = "encrypto"
	KeyPassword = "password"
)

// cipher resolves the encryption from the options, defaulting to the plaintext dummy cipher
// and accepting the legacy base64 "method:password" username form.
func cipher(opts permuteproxy.Options) (shadowsocks.ConnCipher, error) {
	method := opts[KeyUsername]
	if method == "" {
		method = "dummy"
	}
	user := url.User(method)
	if password, ok := opts[KeyPassword]; ok {
		user = url.UserPassword(method, password)
	}
	method, password, err := shadowsocks.GetCipherAndPasswordFromUserinfo(user)
	if err != nil {
		return nil, err
	}
	return shadowsocks.NewCipher(method, password)
}

func NewClient(inner permuteproxy.Transport, _ permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Network, error) {
	connCipher, err := cipher(opts)
	if err != nil {
		return nil, err
	}
	dialer := &shadowsocks.Dialer{
		ConnCipher: connCipher,
		Timeout:    time.Minute,
		ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return inner.Dial(ctx, permuteproxy.Stream)
		},
	}
	return protoutils.DialNetwork(dialer.DialContext, "tcp", "tcp4", "tcp6"), nil
}

func NewServer(inner permuteproxy.Transport, upstream permuteproxy.Network, opts permuteproxy.Options) (permuteproxy.Server, error) {
	connCipher, err := cipher(opts)
	if err != nil {
		return nil, err
	}
	srv := shadowsocks.NewServer()
	srv.ConnCipher = connCipher
	srv.ProxyDial = upstream.DialContext
	srv.BytesPool = pool.Bytes
	return protoutils.NewServer(inner.Listen, func(ctx context.Context, ln net.Listener) error {
		srv.Context = ctx
		return srv.Serve(ln)
	}), nil
}
