package socks4

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.Spec{
		Kind:           permuteproxy.KindProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Client:         NewClient,
		Server:         NewServer,
	}
	permuteproxy.RegisterLayer("socks4", spec)
	permuteproxy.RegisterLayer("socks4s", spec)
}
