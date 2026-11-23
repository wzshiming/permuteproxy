package socks5

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.LayerSpec{
		Kind:           permuteproxy.LayerProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream | permuteproxy.Packet,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Networks:       []string{"tcp", "udp"},
		NewClient:      NewClient,
		NewServer:      NewServer,
	}
	permuteproxy.RegisterLayer("socks5", spec)
	spec.NewClient = NewClientH
	permuteproxy.RegisterLayer("socks5h", spec)
}
