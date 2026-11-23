package sshproxy

import (
	"github.com/wzshiming/sshd"

	"github.com/wzshiming/permuteproxy"
)

func init() {
	permuteproxy.RegisterLayer("ssh", permuteproxy.LayerSpec{
		Kind:           permuteproxy.LayerProxy,
		Requires:       permuteproxy.Stream,
		Provides:       permuteproxy.Stream | permuteproxy.Packet,
		Lossy:          permuteproxy.Packet,
		Options:        options,
		UsernameOption: KeyUsername,
		PasswordOption: KeyPassword,
		Networks:       []string{"tcp", "unix", "cmd"},
		NewClient:      NewClient,
		NewServer:      NewServer,
	})
	sshd.RegistryHandleChannel("session", serveSession)
}
