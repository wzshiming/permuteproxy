package shadowsocks

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	// Preserves grows to Stream|Packet once the UDP side lands.
	spec := permuteproxy.Spec{
		Kind:           permuteproxy.KindProxy,
		Preserves:      permuteproxy.Stream,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Client:         NewClient,
		Server:         NewServer,
	}
	permuteproxy.RegisterLayer("ss", spec)
	permuteproxy.RegisterLayer("shadowsocks", spec)
}
