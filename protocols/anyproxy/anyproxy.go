package anyproxy

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/wzshiming/anyproxy"
	_ "github.com/wzshiming/anyproxy/proxies/httpproxy"
	_ "github.com/wzshiming/anyproxy/proxies/socks4"
	_ "github.com/wzshiming/anyproxy/proxies/socks5"
	_ "github.com/wzshiming/anyproxy/proxies/sshproxy"
	"github.com/wzshiming/cmux/pattern"

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

// prefixes are the cmux patterns the protocols register; cmux gives up on a prefix split across reads.
var prefixes = slices.Concat(pattern.Pattern[pattern.HTTP], pattern.Pattern[pattern.HTTP2], pattern.Pattern[pattern.SOCKS4], pattern.Pattern[pattern.SOCKS5], pattern.Pattern[pattern.SSH])

var maxPrefix = len(slices.MaxFunc(prefixes, func(a, b string) int { return len(a) - len(b) }))

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
		return proxy.Match(host).Serve(sniffListener{ln})
	}), nil
}

// partial reports whether some prefix extends b, so more bytes are needed before matching.
func partial(b []byte) bool {
	for _, p := range prefixes {
		if len(p) > len(b) && strings.HasPrefix(p, string(b)) {
			return true
		}
	}
	return false
}

type sniffListener struct {
	net.Listener
}

func (l sniffListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: conn}, nil
}

// sniffConn holds the first read until it carries a whole prefix or rules every prefix out.
type sniffConn struct {
	net.Conn
	buf     []byte
	sniffed bool
}

func (c *sniffConn) Read(p []byte) (int, error) {
	if !c.sniffed {
		c.sniffed = true
		buf := make([]byte, 0, maxPrefix)
		for partial(buf) {
			n, err := c.Conn.Read(buf[len(buf):cap(buf)])
			buf = buf[:len(buf)+n]
			if err != nil {
				if len(buf) == 0 {
					return 0, err
				}
				break
			}
		}
		c.buf = buf
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
