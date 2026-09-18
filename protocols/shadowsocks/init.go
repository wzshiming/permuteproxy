package shadowsocks

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	spec := permuteproxy.Spec{
		Kind:           permuteproxy.KindProxy,
		Preserves:      permuteproxy.Stream | permuteproxy.Packet,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Client:         NewClient,
		Server:         NewServer,
	}
	permuteproxy.RegisterLayer("ss", spec)
	permuteproxy.RegisterLayer("shadowsocks", spec)
}
