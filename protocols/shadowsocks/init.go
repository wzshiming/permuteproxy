package shadowsocks

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.LayerSpec{
		Kind:        permuteproxy.LayerProxy,
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
