package sshproxy

import (
	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("ssh", permuteproxy.Spec{
		Kind:           permuteproxy.KindProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream,
		Options:        options,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Networks:       []string{"tcp", "unix"},
		NewClient:      NewClient,
		NewServer:      NewServer,
	})
}
