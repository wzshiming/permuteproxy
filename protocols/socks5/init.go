package socks5

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
	permuteproxy.RegisterLayer("socks5", spec)
	spec.Client = NewClientH
	permuteproxy.RegisterLayer("socks5h", spec)
}
