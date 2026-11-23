package httpproxy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("http", permuteproxy.LayerSpec{
		Kind:           permuteproxy.KindProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Networks:       []string{"tcp"},
		NewClient:      NewClient,
		NewServer:      NewServer,
	})
}
