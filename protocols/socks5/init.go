package socks5

import (
	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local" // registers the base networks Networks lists
)

func init() {
	spec := permuteproxy.LayerSpec{
		Requires:    permuteproxy.Stream,
		Provides:    permuteproxy.Stream | permuteproxy.Packet,
		UsernameKey: KeyUsername,
		PasswordKey: KeyPassword,
		Networks:    []string{"tcp", "udp"},
		NewClient:   NewClient,
		NewServer:   NewServer,
	}
	permuteproxy.RegisterLayer("socks5", spec)
	spec.NewClient = NewClientH
	permuteproxy.RegisterLayer("socks5h", spec)
}
