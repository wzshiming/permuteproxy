package socks5

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.Spec{
		Kind:           permuteproxy.KindProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream | permuteproxy.Packet,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Client:         NewClient,
		NewServer:      NewServer,
	}
	permuteproxy.RegisterLayer("socks5", spec)
	spec.Client = NewClientH
	permuteproxy.RegisterLayer("socks5h", spec)
}
