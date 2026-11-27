package socks4

import (
	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/local" // registers the base networks Networks lists
)

func init() {
	spec := permuteproxy.LayerSpec{
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
