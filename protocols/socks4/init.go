package socks4

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.LayerSpec{
		Kind:        permuteproxy.LayerProxy,
		Requires:    permuteproxy.Stream,
		Provides:    permuteproxy.Stream,
		UsernameKey: KeyUsername,
		PasswordKey: KeyPassword,
		Networks:    []string{"tcp"},
		NewClient:   NewClient,
		NewServer:   NewServer,
	}
	permuteproxy.RegisterLayer("socks4", spec)
	permuteproxy.RegisterLayer("socks4a", spec)
}
