package httpproxy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("http", permuteproxy.Spec{
		Kind:           permuteproxy.KindProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Client:         NewClient,
		Server:         NewServer,
	})
}
