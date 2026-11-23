package anyproxy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("any", permuteproxy.LayerSpec{
		Kind:           permuteproxy.KindProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		NewServer:      NewServer,
	})
}
