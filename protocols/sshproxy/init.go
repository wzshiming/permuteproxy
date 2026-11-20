package sshproxy

import (
	"github.com/wzshiming/sshd"

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
		Networks:       []string{"tcp", "unix", "cmd"},
		NewClient:      NewClient,
		NewServer:      NewServer,
	})
	sshd.RegistryHandleChannel("session", serveSession)
}
