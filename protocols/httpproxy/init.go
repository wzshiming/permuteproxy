package httpproxy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("http", permuteproxy.LayerSpec{
		Kind:        permuteproxy.LayerProxy,
		Requires:    permuteproxy.Stream,
		Provides:    permuteproxy.Stream,
		UsernameKey: KeyUsername,
		PasswordKey: KeyPassword,
		Networks:    []string{"tcp"},
		NewClient:   NewClient,
		NewServer:   NewServer,
	})
}
