package sshproxy

import (
	"github.com/wzshiming/sshd"

	"github.com/wzshiming/permuteproxy"
	_ "github.com/wzshiming/permuteproxy/protocols/command" // registers cmd, which Networks lists, and dgram, which the client derives udp through
	_ "github.com/wzshiming/permuteproxy/protocols/local"   // registers the base networks Networks lists
)

func init() {
	permuteproxy.RegisterLayer("ssh", permuteproxy.LayerSpec{
		Requires:    permuteproxy.Stream,
		Provides:    permuteproxy.Stream | permuteproxy.Packet,
		Lossy:       permuteproxy.Packet,
		OptionKeys:  options,
		UsernameKey: KeyUsername,
		PasswordKey: KeyPassword,
		Networks:    []string{"tcp", "unix", "cmd"},
		NewClient:   NewClient,
		NewServer:   NewServer,
	})
	sshd.RegistryHandleChannel("session", serveSession)
}
