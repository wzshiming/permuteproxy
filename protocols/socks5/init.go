package socks5

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	protocols.Registry("socks5", protocols.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind:          protocols.KindProxy,
			Base:          protocols.KindStream,
			UsernameField: "username",
			PasswordField: "password",
			DialSupport: []string{
				"tcp",
			},
		},
		Handle: protocols.Handle{
			NewDialer:     NewSocks5Dialer,
			NewRunnerFunc: NewSocks5Runner,
		},
	})
}
