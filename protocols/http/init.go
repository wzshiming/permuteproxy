package http

import (
	"github.com/wzshiming/permuteproxy/protocols"
)

func init() {
	protocols.Registry("http", protocols.Define{
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
			NewDialerFunc: NewHttpDialer,
			NewRunnerFunc: NewHttpRunner,
		},
	})
}
