package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/wzshiming/shadowsocks"
	_ "github.com/wzshiming/shadowsocks/init"

	"github.com/wzshiming/permuteproxy"
	"github.com/wzshiming/permuteproxy/internal/pool"
)

const (
	KeyEncrypto = "encrypto"
	KeyPassword = "password"
)

// cipher resolves the encryption from the options, defaulting to the plaintext dummy cipher
// and accepting the legacy base64 "method:password" username form.
func cipher(opts permuteproxy.Options) (shadowsocks.Cipher, error) {
	method := opts[KeyEncrypto]
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

func NewClient(opts permuteproxy.Options) (*permuteproxy.ClientFuncs, error) {
	connCipher, err := cipher(opts)
	if err != nil {
		return nil, err
	}
	c := &client{cipher: connCipher}
	return &permuteproxy.ClientFuncs{Dial: c.dial, ListenPacket: c.listenPacket}, nil
}

// client carries tcp over the inner stream plane and udp over its packet plane with one cipher.
type client struct {
	cipher shadowsocks.Cipher
}

func (c *client) dial(ctx context.Context, inner permuteproxy.Transport, network, address string) (net.Conn, error) {
	dialer := &shadowsocks.Dialer{
		Cipher:  c.cipher,
		Timeout: time.Minute,
		ProxyDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return inner.Dial(ctx, permuteproxy.Stream)
		},
	}
	return dialer.DialContext(ctx, network, address)
}

// listenPacket opens one datagram carrier to the proxy; WriteTo and ReadFrom name the targets.
func (c *client) listenPacket(ctx context.Context, inner permuteproxy.Transport, _ permuteproxy.Network, _, _ string) (net.PacketConn, error) {
	conn, err := inner.Dial(ctx, permuteproxy.Packet)
	if err != nil {
		return nil, err
	}
	carrier, ok := conn.(net.PacketConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("packet carrier %T is not a net.PacketConn", conn)
	}
	// The library resolves ProxyAddress before asking for the socket, so it is built per dial from
	// the carrier's actual peer.
	pc := &shadowsocks.PacketClient{
		ProxyNetwork: "udp",
		ProxyAddress: conn.RemoteAddr().String(),
		ProxyPacket:  func(context.Context, string, string) (net.PacketConn, error) { return carrier, nil },
		Cipher:       c.cipher,
		BytesPool:    pool.Bytes,
	}
	wrapped, err := pc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		conn.Close()
		return nil, err
	}
	return wrapped, nil
}

func NewServer(opts permuteproxy.Options) (*permuteproxy.ServerFuncs, error) {
	connCipher, err := cipher(opts)
	if err != nil {
		return nil, err
	}
	serveStream := func(ctx context.Context, ln net.Listener, upstream permuteproxy.Network) error {
		srv := shadowsocks.NewServer()
		srv.Context = ctx
		srv.Cipher = connCipher
		srv.ProxyDial = upstream.DialContext
		srv.BytesPool = pool.Bytes
		return srv.Serve(ln)
	}
	servePacket := func(ctx context.Context, pc net.PacketConn, upstream permuteproxy.Network) error {
		psrv := shadowsocks.NewPacketServer()
		psrv.Context = ctx
		psrv.Cipher = connCipher
		psrv.ProxyPacket = upstream.ListenPacket
		psrv.BytesPool = pool.Bytes
		psrv.Timeout = time.Minute
		// The library skips the datagrams it cannot decrypt or parse and closes the outgoing sockets it opened.
		return psrv.ServePacket(pc)
	}
	return &permuteproxy.ServerFuncs{Serve: serveStream, ServePacket: servePacket}, nil
}
