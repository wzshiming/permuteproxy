package shadowsocks

import (
	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local" // registers the base networks Networks lists
)

func init() {
	spec := permuteproxy.LayerSpec{
		Preserves:   permuteproxy.Stream | permuteproxy.Packet,
		Networks:    []string{"tcp", "udp"},
		UsernameKey: KeyEncrypto,
		PasswordKey: KeyPassword,
		NewClient:   NewClient,
		NewServer:   NewServer,
	}
	permuteproxy.RegisterLayer("ss", spec)
	permuteproxy.RegisterLayer("shadowsocks", spec)
}
