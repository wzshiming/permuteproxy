package shadowsocks

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.LayerSpec{
		Kind:           permuteproxy.KindProxy,
		Preserves:      permuteproxy.Stream | permuteproxy.Packet,
		Networks:       []string{"tcp", "udp"},
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		NewClient:      NewClient,
		NewServer:      NewServer,
	}
	permuteproxy.RegisterLayer("ss", spec)
	permuteproxy.RegisterLayer("shadowsocks", spec)
}
