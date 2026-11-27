package anyproxy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("any", permuteproxy.LayerSpec{
		Requires:    permuteproxy.Stream,
		Provides:    permuteproxy.Stream,
		UsernameKey: KeyUsername,
		PasswordKey: KeyPassword,
		NewServer:   NewServer,
	})
}
