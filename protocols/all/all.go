// Package all registers every bundled network and layer.
package all

import (
	_ "github.com/wzshiming/permuteproxy/protocols/anyproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/httpproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local"
	_ "github.com/wzshiming/permuteproxy/protocols/quic"
	_ "github.com/wzshiming/permuteproxy/protocols/shadowsocks"
	_ "github.com/wzshiming/permuteproxy/protocols/snappy"
	_ "github.com/wzshiming/permuteproxy/protocols/socks4"
	_ "github.com/wzshiming/permuteproxy/protocols/socks5"
	_ "github.com/wzshiming/permuteproxy/protocols/sshproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/tls"
)
