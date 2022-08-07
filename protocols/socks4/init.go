package socks4

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	protocols.Registry("socks4", protocols.Define{
		SchemeInfo: protocols.SchemeInfo{
			Kind:          protocols.KindProxy,
			Base:          protocols.KindStream,
			UsernameField: "username",
			DialSupport: []string{
				"tcp",
			},
		},
		Handle: protocols.Handle{
			NewDialer:     NewSocks4Dialer,
			NewRunnerFunc: NewSocks4Runner,
		},
	})
}
